// Command agent is the UnifiedGuard device agent (Linux first, Windows later).
// Subcommands:
//
//	unifiedguard-agent version                     → build info + self-hash (N12)
//	unifiedguard-agent enroll --hub URL --token T  → one-time enrollment (PLAN §3.1)
//	unifiedguard-agent run                        → service loop (systemd)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"git.dpnac.cloud/dpnac/central/agent/enroll"
	linux "git.dpnac.cloud/dpnac/central/agent/platform/linux"
	"git.dpnac.cloud/dpnac/central/agent/runtime"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("unifiedguard-agent %s\nself-hash %s\n", version.String(), version.SelfHash())
			return
		case "enroll":
			cmdEnroll(os.Args[2:])
			return
		case "run":
			cmdRun(os.Args[2:])
			return
		}
	}
	fmt.Printf("unifiedguard-agent %s\n\nusage: unifiedguard-agent <version|enroll|run>\n", version.String())
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	hubURL := fs.String("hub", "", "hub base URL, e.g. https://central.acme.fr")
	token := fs.String("token", "", "enrollment token (ug-...)")
	stateDir := fs.String("state", enroll.StateDir, "state directory")
	_ = fs.Parse(args)

	if *hubURL == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll: --hub and --token are required")
		os.Exit(2)
	}
	osName, osVersion, arch := linux.DetectOS()
	hn, _ := os.Hostname()
	id, err := enroll.Enroll(*hubURL, *token, *stateDir, protocol.HostCore{
		Hostname: hn, OS: osName, OSVersion: osVersion, Arch: arch,
		AgentVersion: version.String(), AgentHash: version.SelfHash(),
	})
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	fmt.Printf("enrolled as %s (identity in %s)\n", id.AgentID, *stateDir)
	fmt.Println("next: systemctl enable --now unifiedguard-agent")
}

func cmdRun(args []string) {
	_ = args
	stateDir := os.Getenv("AGENT_STATE_DIR")
	if stateDir == "" {
		stateDir = enroll.StateDir
	}
	id, err := enroll.LoadIdentity(stateDir)
	if err != nil {
		log.Fatalf("run: load identity: %v (did you enroll?)", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("agent %s starting (state: %s)", id.AgentID, stateDir)
	if err := runtime.Run(ctx, id, runtime.Default()); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
}
