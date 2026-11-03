// Package protocol defines the versioned wire contract between agents,
// hubs (centrales) and the fleet console. Everything is JSON with a "v"
// field; adding a field is backward compatible, changing one requires a
// new protocol version.
//
// Golden rule (SPEC §2.1): the agent ALWAYS initiates the connection.
// Hub→agent messages travel on the very WebSocket the agent opened.
package protocol

import (
	"encoding/json"
	"time"
)

// V is the current protocol version.
const V = 1

// Envelope is the single wire format. Every message (both directions) is
// wrapped in this structure.
type Envelope struct {
	V    int             `json:"v"`
	ID   string          `json:"id"`   // message id (UUID)
	Type string          `json:"type"` // heartbeat, telemetry, ping, pong, action...
	TS   time.Time       `json:"ts"`
	Data json.RawMessage `json:"data"`
}

// Message types (both directions share the namespace).
const (
	TypeHeartbeat    = "heartbeat"     // agent → hub, every 30s
	TypeTelemetry    = "telemetry"     // agent → hub, every 5min
	TypeInventory    = "inventory"     // agent → hub, every 24h or on demand
	TypePing         = "ping"          // hub → agent (applicative ping, NEVER ICMP)
	TypePong         = "pong"          // agent → hub, ref = ping id
	TypeAction       = "action"        // hub → agent
	TypeActionResult = "action_result" // agent → hub
	TypeFWState      = "fw_state"      // agent → hub (canonical ruleset hash, drift N3)
	TypeFWConfirm    = "fw_confirm"    // hub → agent (commit-confirm)
	TypeFWSnapshot   = "fw_snapshot"   // agent → hub (encrypted ruleset snapshot, J4)
	TypeEnroll       = "enroll"        // agent → hub (HTTP POST, not on the WS)
)

// HostCore identifies an agent in enroll + heartbeats.
type HostCore struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"` // "debian", "almalinux", "windows"...
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
	AgentHash    string `json:"agent_hash"` // N12 self-hash
}

// FirewallState is reported in every heartbeat (SPEC §3.2).
type FirewallState struct {
	Type    string `json:"type"`    // nftables | firewalld | ufw | iptables-legacy | windows-defender
	Backend string `json:"backend"` // nft | iptables | firewalld | wf
	Version string `json:"version"`
	Active  bool   `json:"active"`
	Mode    string `json:"mode"` // runtime | permanent | both
}

// Heartbeat is the light-weight 30s signal.
type Heartbeat struct {
	HostCore
	FW        FirewallState `json:"fw"`
	UptimeSec int64         `json:"uptime_sec"`
	CPUPct    float64       `json:"cpu_pct"`
	MemPct    float64       `json:"mem_pct"`
}

// Telemetry is the full 5min report.
type Telemetry struct {
	CPU   float64        `json:"cpu_pct"`
	Mem   float64        `json:"mem_pct"`
	Load1 float64        `json:"load1"`
	Disks []DiskUsage    `json:"disks"`
	Net   []NetUsage     `json:"net"`
	Procs []ServiceState `json:"services"`
}

type DiskUsage struct {
	Device     string  `json:"device"`
	Mount      string  `json:"mount"`
	TotalBytes uint64  `json:"total_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"`
}

type NetUsage struct {
	Iface    string `json:"iface"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

type ServiceState struct {
	Name   string `json:"name"`
	Status string `json:"status"` // running | stopped | failed
}

// Package is one entry of the inventory.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// Inventory is the full package list + available updates.
type Inventory struct {
	Packages []Package         `json:"packages"`
	Updates  []UpdateCandidate `json:"updates"`
}

type UpdateCandidate struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Candidate string `json:"candidate"`
	Security  bool   `json:"security"`
}

// Ping/Pong payloads.
type Ping struct{}
type Pong struct {
	Ref string    `json:"ref"`
	TS  time.Time `json:"ts"`
}

// Action is a hub→agent command queued offline (idea 2).
type Action struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"` // pkg_update, fw_apply, inventory_refresh...
	Payload json.RawMessage `json:"payload"`
}

// ActionResult is the agent's terminal answer.
type ActionResult struct {
	ID     string          `json:"id"`
	Status string          `json:"status"` // done | failed | timeout | canceled
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// FWApply is the fw_apply action payload (J4, SPEC §3.5). The agent applies
// the rules in RUNTIME mode only, starts the countdown and rolls back to the
// snapshot unless fw_confirm arrives before the deadline.
type FWApply struct {
	SessionID  string   `json:"session_id"`   // fw_sessions row
	FWType     string   `json:"fw_type"`      // detected stack: nftables | ufw | firewalld | iptables-legacy
	TTLSec     int      `json:"ttl_s"`        // countdown (default 300)
	Rules      []FWRule `json:"rules"`        // the ruleset to apply
	SitePubKey string   `json:"site_pub_key"` // PEM, to encrypt the snapshot up
}

// FWRule is one declarative rule (subset v1: allow/deny + ports).
type FWRule struct {
	Direction string `json:"direction"` // in | out
	Action    string `json:"action"`    // allow | deny | reject
	Proto     string `json:"proto"`     // tcp | udp | any
	Port      string `json:"port"`      // "22", "80", "1000:2000", "" = any
	Source    string `json:"source"`    // CIDR or "" = anywhere
	Comment   string `json:"comment"`   // audit trail on the host
}

// FWSnapshot is the agent→hub encrypted ruleset snapshot (§6.3 envelope).
// The hub stores it opaque: ciphertext = AES-256-GCM(plaintext ruleset),
// wrapped_key = RSA-OAEP(data key, site public key). Only the site private
// key (hub) can unwrap → the fleet/another hub sees noise.
type FWSnapshot struct {
	SessionID  string `json:"session_id"`
	ActionID   string `json:"action_id"`
	FWType     string `json:"fw_type"`     // nftables | firewalld | ufw | iptables-legacy
	Ciphertext []byte `json:"ciphertext"`  // base64 in JSON
	Nonce      []byte `json:"nonce"`       // AES-GCM nonce
	WrappedKey []byte `json:"wrapped_key"` // RSA-OAEP(data key)
	SHA256     string `json:"sha256"`      // digest of the PLAINTEXT (restore check)
	SizeBytes  int    `json:"size_bytes"`
}

// FWConfirm is the hub→agent commit (SPEC §3.5 step 4). The agent keeps its
// rules only if it receives this BEFORE its own deadline.
type FWConfirm struct {
	SessionID string `json:"session_id"`
}
