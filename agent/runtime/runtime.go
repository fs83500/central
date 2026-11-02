// Package runtime is the agent main loop: it opens the WebSocket to the hub
// (the AGENT always initiates — golden rule SPEC §2.1), sends heartbeats
// every 30 s, telemetry every 5 min, inventory every 24 h, and reconnects
// with exponential backoff + jitter.
package runtime

import (
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"git.dpnac.cloud/dpnac/central/agent/enroll"
	linux "git.dpnac.cloud/dpnac/central/agent/platform/linux"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/version"
	"github.com/gorilla/websocket"
)

// Config tunes the loop (defaults follow PLAN §3.2).
type Config struct {
	HeartbeatEvery time.Duration // 30 s
	TelemetryEvery time.Duration // 5 min
	InventoryEvery time.Duration // 24 h
	MinBackoff     time.Duration // 1 s
	MaxBackoff     time.Duration // 60 s
}

// Default returns the protocol v1 timings.
func Default() Config {
	return Config{
		HeartbeatEvery: 30 * time.Second,
		TelemetryEvery: 5 * time.Minute,
		InventoryEvery: 24 * time.Hour,
		MinBackoff:     time.Second,
		MaxBackoff:     60 * time.Second,
	}
}

// Run blocks forever: connect → heartbeat/telemetry/inventory → on error,
// backoff and reconnect. ctx cancellation stops the loop.
func Run(ctx context.Context, id *enroll.Identity, cfg Config) error {
	if id == nil {
		return fmt.Errorf("runtime: nil identity")
	}
	core := hostCore()
	invEvery := cfg.InventoryEvery
	telEvery := cfg.TelemetryEvery
	hbEvery := cfg.HeartbeatEvery

	backoff := cfg.MinBackoff
	for {
		if err := runOnce(ctx, id, core, hbEvery, telEvery, invEvery); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("runtime: connection lost: %v — reconnecting in %s", err, backoff)
			select {
			case <-time.After(backoff + jitter(backoff)):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, cfg.MaxBackoff)
		} else {
			backoff = cfg.MinBackoff // clean close → reset
		}
	}
}

// runOnce is one connection session.
func runOnce(ctx context.Context, id *enroll.Identity, core protocol.HostCore, hb, tel, inv time.Duration) error {
	dialer := wsDialer(id)
	// gorilla expects ws:// or wss://: normalize http(s):// from the
	// enrollment (identity.json stores the hub base URL as given).
	wsURL := strings.Replace(id.HubURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/agent/v1/ws"
	ws, resp, err := dialer.Dial(wsURL, nil) // #nosec G115
	if err != nil {
		if resp != nil {
			defer func() { _ = resp.Body.Close() }() //nolint:bodyclose // closed here, below gorilla takes over on success
			return fmt.Errorf("dial: %w (HTTP %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("dial: %w", err)
	}
	if resp != nil {
		_ = resp.Body.Close() // gorilla buffers the handshake; the body is drained and closed
	}
	defer func() { _ = ws.Close() }()
	log.Printf("runtime: connected to %s", wsURL)

	// Tickers: heartbeat, telemetry, inventory.
	hbT := time.NewTicker(hb)
	defer hbT.Stop()
	var telT *time.Ticker
	var invT *time.Ticker
	if tel > 0 {
		telT = time.NewTicker(tel)
		defer telT.Stop()
	}
	if inv > 0 {
		invT = time.NewTicker(inv)
		defer invT.Stop()
	}

	// Immediate heartbeat on connect (so the hub sees us online at once).
	if err := sendEnvelope(ws, protocol.TypeHeartbeat, heartbeat(core)); err != nil {
		return err
	}

	errCh := make(chan error, 4)
	// Reader goroutine: consumes hub messages (ping/action/...). J1: only
	// pong-less ping answers + discard unknown. Actions arrive in J3.
	go func() {
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				errCh <- err
				return
			}
			switch env.Type {
			case protocol.TypePing:
				pong := protocol.Pong{Ref: env.ID}
				data, _ := json.Marshal(pong)
				_ = ws.WriteControl(0, nil, time.Time{}) // keepalive no-op
				out := protocol.Envelope{V: protocol.V, ID: env.ID, Type: protocol.TypePong, TS: time.Now().UTC(), Data: data}
				if err := ws.WriteJSON(out); err != nil {
					errCh <- err
					return
				}
			default:
				// J3 will handle action / fw_confirm; J1 ignores unknown types.
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = ws.Close()
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-hbT.C:
			if err := sendEnvelope(ws, protocol.TypeHeartbeat, heartbeat(core)); err != nil {
				return err
			}
		case <-tickerChan(telT):
			t, err := telemetry()
			if err == nil {
				if err := sendEnvelope(ws, protocol.TypeTelemetry, t); err != nil {
					return err
				}
			}
		case <-tickerChan(invT):
			i := protocol.Inventory{Packages: linux.Packages(), Updates: linux.Updates()}
			if err := sendEnvelope(ws, protocol.TypeInventory, i); err != nil {
				return err
			}
		}
	}
}

func tickerChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func sendEnvelope(ws *wsConn, typ string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ws.WriteJSON(protocol.Envelope{V: protocol.V, ID: newID(), Type: typ, TS: time.Now().UTC(), Data: raw})
}

func heartbeat(core protocol.HostCore) protocol.Heartbeat {
	core.AgentVersion = version.String()
	core.AgentHash = version.SelfHash()
	cpu, mem := linux.CPUandMem()
	return protocol.Heartbeat{
		HostCore:  core,
		FW:        linux.DetectFirewall(),
		UptimeSec: linux.UptimeSec(),
		CPUPct:    cpu,
		MemPct:    mem,
	}
}

func telemetry() (protocol.Telemetry, error) {
	cpu, mem := linux.CPUandMem()
	return protocol.Telemetry{
		CPU:   cpu,
		Mem:   mem,
		Load1: linux.Load1(),
		Disks: linux.Disks(),
	}, nil
}

func hostCore() protocol.HostCore {
	osName, osVersion, arch := linux.DetectOS()
	hn, _ := osHostname()
	return protocol.HostCore{
		Hostname: hn, OS: osName, OSVersion: osVersion, Arch: arch,
	}
}

func jitter(d time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(d/2) + 1)) //nolint:gosec // jitter only
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	return next
}

// tlsConfig builds the mTLS client config from the identity.
func tlsConfig(id *enroll.Identity) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(id.CAPool) {
		return nil, fmt.Errorf("runtime: hub CA chain invalid")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func wsDialer(id *enroll.Identity) *websocketDialer {
	tlsCfg, err := tlsConfig(id)
	if err != nil {
		return &websocketDialer{err: err}
	}
	return &websocketDialer{tls: tlsCfg}
}

// --- small wrappers to keep the API surface tiny --------------------------

type wsConn struct{ c *websocket.Conn }

func (w *wsConn) WriteJSON(v any) error { return w.c.WriteJSON(v) }
func (w *wsConn) ReadJSON(v any) error  { return w.c.ReadJSON(v) }
func (w *wsConn) WriteControl(code int, data []byte, deadline time.Time) error {
	return w.c.WriteControl(websocket.CloseMessage, nil, time.Now().Add(time.Second))
}
func (w *wsConn) Close() error { return w.c.Close() }

type websocketDialer struct {
	tls *tls.Config
	err error
}

func (d *websocketDialer) Dial(url string, _ http.Header) (*wsConn, *http.Response, error) {
	if d.err != nil {
		return nil, nil, d.err
	}
	dialer := websocket.Dialer{TLSClientConfig: d.tls, HandshakeTimeout: 15 * time.Second}
	c, resp, err := dialer.Dial(url, nil)
	if err != nil {
		return nil, resp, err
	}
	return &wsConn{c: c}, resp, nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return time.Now().Format("150405.000000000")
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func osHostname() (string, error) {
	return os.Hostname()
}

var _ = ecdsa.PrivateKey{}
var _ = pem.Block{}
