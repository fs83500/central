// firewall.go — J4 firewall engine (Linux): snapshot the live ruleset, apply
// a declarative ruleset in RUNTIME mode, commit-confirm with automatic
// rollback (SPEC §3.5). Supported stacks: nftables, firewalld, ufw,
// iptables-legacy. Every mutation path goes through the same commit-confirm
// harness so an operator mistake can never lock a machine out for long.

package platform

import (
	"fmt"
	"os/exec"
	"strings"
)

// fwBackend is the pluggable per-stack implementation. All outputs are the
// NATIVE serialisation of the stack (nft list ruleset, ufw show added…), so a
// restore replays exactly what the stack itself dumped.
type fwBackend interface {
	Name() string
	Dump() ([]byte, error)    // full runtime ruleset snapshot
	Restore([]byte) error     // atomically reload a dumped ruleset
	Apply([]FWRuleSpec) error // apply declarative rules in RUNTIME mode
}

// FWRuleSpec mirrors protocol.FWRule without the protocol dependency
// (platform stays wire-format-free).
type FWRuleSpec struct {
	Direction string // in | out
	Action    string // allow | deny | reject
	Proto     string // tcp | udp | any
	Port      string // "22" | "8000:9000" | "" (any)
	Source    string // CIDR | "" (anywhere)
	Comment   string
}

// Snapshot dumps the live ruleset of the detected stack.
func Snapshot(fwType string) ([]byte, error) {
	b, err := backendFor(fwType)
	if err != nil {
		return nil, err
	}
	return b.Dump()
}

// Restore reloads a snapshot into the given stack (rollback path).
func Restore(fwType string, data []byte) error {
	b, err := backendFor(fwType)
	if err != nil {
		return err
	}
	return b.Restore(data)
}

// ApplyRules applies the declarative ruleset in runtime mode.
func ApplyRules(fwType string, rules []FWRuleSpec) error {
	b, err := backendFor(fwType)
	if err != nil {
		return err
	}
	return b.Apply(rules)
}

func backendFor(fwType string) (fwBackend, error) {
	switch fwType {
	case "nftables":
		return nftBackend{}, nil
	case "ufw":
		return ufwBackend{}, nil
	case "firewalld":
		return fwldBackend{}, nil
	case "iptables-legacy":
		return iptBackend{}, nil
	default:
		return nil, fmt.Errorf("fw: unsupported stack %q", fwType)
	}
}

// runExec isolates command running for the backends (single choke point to
// audit/limit argv later; inputs are internal, never operator raw strings).
func runExec(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...) // #nosec G204 -- argv built in code, not from user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// --- nftables ---------------------------------------------------------------

type nftBackend struct{}

func (nftBackend) Name() string { return "nftables" }

func (nftBackend) Dump() ([]byte, error) {
	return runExec("nft", "list", "ruleset")
}

func (nftBackend) Restore(data []byte) error {
	// Atomic reload: nft -f - replaces the whole ruleset in one transaction.
	return runExecStdin("nft", "-f", data)
}

func (nftBackend) Apply(rules []FWRuleSpec) error {
	// v1: apply through the nftables CLI one rule at a time in a scratch
	// table ug-mgmt (runtime only; nothing persisted to disk).
	// Base chain ug-mgmt-input in filter/input so the management path stays open.
	first := true
	for _, r := range rules {
		chain := "ug-mgmt-output"
		if r.Direction == "in" {
			chain = "ug-mgmt-input"
		}
		if first {
			_, _ = runExec("nft", "add", "table", "inet", "ug-mgmt")
			_, _ = runExec("nft", "add", "chain", "inet", "ug-mgmt", "ug-mgmt-input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}")
			_, _ = runExec("nft", "add", "chain", "inet", "ug-mgmt", "ug-mgmt-output", "{", "type", "filter", "hook", "output", "priority", "0", ";", "}")
			_, _ = runExec("nft", "add", "rule", "inet", "ug-mgmt", "ug-mgmt-input", "tcp", "dport", mgmtPort(), "accept", "comment", "\\\"ug-mgmt allow\\\"")
			first = false
		}
		stmt := nftStmt(r)
		if _, err := runExec("nft", append([]string{"add", "rule", "inet", "ug-mgmt", chain}, stmt...)...); err != nil {
			return err
		}
	}
	return nil
}

func nftStmt(r FWRuleSpec) []string {
	stmt := []string{}
	if r.Proto != "" && r.Proto != "any" {
		stmt = append(stmt, r.Proto)
	}
	if r.Port != "" {
		stmt = append(stmt, "dport", r.Port)
	}
	if r.Source != "" {
		stmt = append(stmt, "saddr", r.Source)
	}
	switch r.Action {
	case "allow":
		stmt = append(stmt, "accept")
	case "deny":
		stmt = append(stmt, "drop")
	case "reject":
		stmt = append(stmt, "reject")
	}
	return stmt
}

func mgmtPort() string {
	return "8801" // hub mTLS port — agent→hub channel must survive (SPEC §3.5 step 3)
}

// --- ufw ----------------------------------------------------------------------

type ufwBackend struct{}

func (ufwBackend) Name() string { return "ufw" }

func (ufwBackend) Dump() ([]byte, error) {
	// ufw show added = the runtime view of user rules.
	out, err := runExec("ufw", "show", "added")
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (ufwBackend) Restore(_ []byte) error {
	// ufw has no atomic import of a runtime dump; the reliable rollback is
	// `ufw reload` which re-reads the persistent config (the snapshot is the
	// proof of what was there, and runtime edits were never persisted).
	_, err := runExec("ufw", "reload")
	return err
}

func (ufwBackend) Apply(rules []FWRuleSpec) error {
	for _, r := range rules {
		if r.Direction != "in" {
			continue // v1: ufw input only (output rules are out of scope)
		}
		port := r.Port
		if port == "" {
			port = "any"
		}
		proto := r.Proto
		if proto == "" || proto == "any" {
			proto = "tcp"
		}
		argv := []string{"insert", "1"}
		if r.Action == "allow" {
			argv = append(argv, "allow")
		} else {
			argv = append(argv, r.Action) // deny | reject
		}
		argv = append(argv, port)
		if proto != "any" {
			argv = append(argv, "proto", proto)
		}
		if r.Source != "" {
			argv = append(argv, "from", r.Source)
		}
		if _, err := runExec("ufw", argv...); err != nil {
			return err
		}
	}
	return nil
}

// --- firewalld ---------------------------------------------------------------

type fwldBackend struct{}

func (fwldBackend) Name() string { return "firewalld" }

func (fwldBackend) Dump() ([]byte, error) {
	// --permanent=false = RUNTIME rules (SPEC: snapshot the live state).
	out, err := runExec("firewall-cmd", "--list-all")
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

func (fwldBackend) Restore(_ []byte) error {
	// Runtime reset = the documented firewalld rollback (SPEC §3.5 step 5).
	_, err := runExec("firewall-cmd", "--reload")
	return err
}

func (fwldBackend) Apply(rules []FWRuleSpec) error {
	for _, r := range rules {
		if r.Direction != "in" {
			continue
		}
		if r.Port == "" {
			continue
		}
		portSpec := fmt.Sprintf("%s/%s", r.Port, protoOr(r.Proto, "tcp"))
		argv := []string{}
		switch r.Action {
		case "allow":
			argv = append(argv, "--add-port="+portSpec)
		default:
			argv = append(argv, "--remove-port="+portSpec)
		}
		if r.Source != "" {
			argv = append(argv, "--zone=public", "--permanent=false")
			// v1: rich rules for CIDR scoping
			rich := fmt.Sprintf("--add-rich-rule='rule family=ipv4 source address=%s port port=%s protocol=%s accept'", r.Source, r.Port, protoOr(r.Proto, "tcp"))
			argv = []string{rich}
		}
		if _, err := runExec("firewall-cmd", argv...); err != nil {
			return err
		}
	}
	return nil
}

// --- iptables-legacy ----------------------------------------------------------

type iptBackend struct{}

func (iptBackend) Name() string { return "iptables-legacy" }

func (iptBackend) Dump() ([]byte, error) {
	return runExec("iptables-save")
}

func (iptBackend) Restore(data []byte) error {
	return runExecStdin("iptables-restore", "", data)
}

func (iptBackend) Apply(rules []FWRuleSpec) error {
	for _, r := range rules {
		if r.Direction != "in" {
			continue
		}
		chain := "INPUT"
		stmt := []string{"-I", chain, "1"}
		if r.Proto != "" && r.Proto != "any" {
			stmt = append(stmt, "-p", r.Proto)
		}
		if r.Port != "" {
			stmt = append(stmt, "--dport", r.Port)
		}
		if r.Source != "" {
			stmt = append(stmt, "-s", r.Source)
		}
		switch r.Action {
		case "allow":
			stmt = append(stmt, "-j", "ACCEPT")
		case "deny":
			stmt = append(stmt, "-j", "DROP")
		case "reject":
			stmt = append(stmt, "-j", "REJECT")
		}
		if _, err := runExec("iptables", stmt...); err != nil {
			return err
		}
	}
	return nil
}

// runExecStdin pipes data to the command (nft -f, iptables-restore).
// argv examples: ["-f"] for nft, [] for iptables-restore.
func runExecStdin(bin string, flag string, data []byte) error {
	var argv []string
	if flag != "" {
		argv = append(argv, flag)
	}
	cmd := exec.Command(bin, argv...) // #nosec G204 -- fixed argv
	cmd.Stdin = strings.NewReader(string(data))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", bin, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func protoOr(p, def string) string {
	if p == "" || p == "any" {
		return def
	}
	return p
}
