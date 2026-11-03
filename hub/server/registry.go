package server

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// agentRegistry tracks live agent WebSockets so the hub can push messages
// (ping, actions) on the very channel the AGENT opened — golden rule SPEC
// §2.1: the hub never dials out to a device.
type agentRegistry struct {
	mu    sync.RWMutex
	conns map[string]*agentConn
}

// agentConn is one live agent connection with its own outbound queue.
type agentConn struct {
	ws   *websocket.Conn
	send chan []byte // pre-marshaled envelopes, written by writer()
}

func newRegistry() *agentRegistry {
	return &agentRegistry{conns: map[string]*agentConn{}}
}

// add registers a live connection. If the agent already had one, the old
// connection is replaced (last wins — the agent reconnect loop may open the
// new socket before the hub notices the old one dying).
func (r *agentRegistry) add(agentID string, ws *websocket.Conn) *agentConn {
	c := &agentConn{ws: ws, send: make(chan []byte, 64)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.conns[agentID]; ok {
		_ = old.ws.Close()
	}
	r.conns[agentID] = c
	return c
}

func (r *agentRegistry) remove(agentID string, c *agentConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.conns[agentID]; ok && cur == c {
		delete(r.conns, agentID)
	}
}

// get returns the live connection for an agent (nil if offline).
func (r *agentRegistry) get(agentID string) *agentConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[agentID]
}

// count returns how many agents are connected right now.
func (r *agentRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.conns)
}

// pingWaiters maps in-flight ping envelope IDs → the channel receiving the
// measured RTT (milliseconds) when the pong lands.
var (
	pingMu      sync.Mutex
	pingWaiters = map[string]chan int64{}
)

// waitPong registers a waiter for a ping id. Returns the RTT in ms or -1 if
// no pong arrived within d.
func waitPong(id string, d time.Duration) int64 {
	ch := make(chan int64, 1)
	pingMu.Lock()
	pingWaiters[id] = ch
	pingMu.Unlock()
	defer func() {
		pingMu.Lock()
		delete(pingWaiters, id)
		pingMu.Unlock()
	}()
	select {
	case rtt := <-ch:
		return rtt
	case <-time.After(d):
		return -1
	}
}

// resolvePong completes a pending ping (returns false if it already timed out).
func resolvePong(id string, rtt int64) bool {
	pingMu.Lock()
	ch, ok := pingWaiters[id]
	if ok {
		delete(pingWaiters, id)
	}
	pingMu.Unlock()
	if ok {
		ch <- rtt
		return true
	}
	return false
}
