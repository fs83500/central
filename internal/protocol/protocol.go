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
