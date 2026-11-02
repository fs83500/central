// Package platform abstracts OS-specific collection. Linux implementation:
// telemetry from /proc, packages from dpkg, firewall detection read-only
// (nftables / firewalld / ufw — SPEC §3.2). Windows arrives in J8.
package platform

import (
	"bufio"
	"os"
	"os/exec"

	"strconv"
	"strings"
	"syscall"
	"time"

	"git.dpnac.cloud/dpnac/central/internal/protocol"
)

// DetectOS returns the OS identity (linux distribution).
func DetectOS() (osName, osVersion, arch string) {
	arch = goArch()
	if b, err := os.ReadFile("/etc/os-release"); err == nil { // #nosec G304 -- fixed path
		m := parseOSRelease(string(b))
		return m["ID"], m["VERSION_ID"], arch
	}
	return "linux", "", arch
}

// UptimeSec reads /proc/uptime.
func UptimeSec() int64 {
	b, err := os.ReadFile("/proc/uptime") // #nosec G304 -- fixed path
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0
	}
	sec, _ := strconv.ParseFloat(strings.Split(f[0], ",")[0], 64)
	return int64(sec)
}

// CPUandMem returns cpu and memory usage percentages from /proc.
func CPUandMem() (cpu, mem float64) {
	return cpuPercent(), memPercent()
}

// Load1 returns the 1-minute load average (0 on non-Linux).
func Load1() float64 {
	b, err := os.ReadFile("/proc/loadavg") // #nosec G304 -- fixed path
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// Disks lists mounted filesystems usage (df-like, from /proc/mounts +
// statfs on real filesystems).
func Disks() []protocol.DiskUsage {
	var out []protocol.DiskUsage
	seen := map[string]bool{}
	if f, err := os.Open("/proc/mounts"); err == nil { // #nosec G304 -- fixed path
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			dev, mount := fields[0], fields[1]
			if seen[mount] || !strings.HasPrefix(dev, "/dev/") {
				continue
			}
			seen[mount] = true
			out = append(out, diskUsage(mount, dev))
		}
	}
	if !seen["/"] {
		out = append([]protocol.DiskUsage{diskUsage("/", "/dev/root")}, out...)
	}
	return out
}

// diskUsage stats one mount point via syscall.Statfs.
func diskUsage(mount, dev string) protocol.DiskUsage {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mount, &st); err != nil {
		return protocol.DiskUsage{Device: dev, Mount: mount}
	}
	total := uint64(st.Bsize) * uint64(st.Blocks) //nolint:gosec // statfs sizes are positive
	avail := uint64(st.Bsize) * uint64(st.Bavail) //nolint:gosec // statfs sizes are positive
	used := total - avail
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return protocol.DiskUsage{
		Device: dev, Mount: mount,
		TotalBytes: total, UsedBytes: used, UsedPct: pct,
	}
}

// Packages reads the dpkg database (fast path: status file; no dpkg query
// subprocess needed). Falls back to empty list if unavailable.
func Packages() []protocol.Package {
	var out []protocol.Package
	f, err := os.Open("/var/lib/dpkg/status") // #nosec G304 -- fixed path
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var cur protocol.Package
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = protocol.Package{}
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			cur.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		} else if strings.HasPrefix(line, "Version:") {
			cur.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Architecture:") {
			cur.Arch = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		}
	}
	flush()
	return out
}

// Updates runs `apt-get --simulate` style check via apt list --upgradable.
// Read-only: never installs anything.
func Updates() []protocol.UpdateCandidate {
	var out []protocol.UpdateCandidate
	cmd := exec.Command("apt-get", "-s", "dist-upgrade") // #nosec G204 -- fixed argv, read-only simulate
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		// Inst <name> (1.0 Debian:1.1 [amd64])
		if strings.HasPrefix(line, "Inst ") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				out = append(out, protocol.UpdateCandidate{Name: f[1], Security: strings.Contains(line, "-security")})
			}
		}
	}
	return out
}

// DetectFirewall returns the active firewall stack (read-only detection,
// SPEC §3.2). Order: firewalld > ufw > nftables > iptables-legacy > none.
func DetectFirewall() protocol.FirewallState {
	// firewalld: systemctl active + firewalld binary present
	if active, _ := systemdActive("firewalld"); active {
		return protocol.FirewallState{Type: "firewalld", Backend: "firewalld", Version: cmdVersion("firewall-cmd", "--version"), Active: true, Mode: "runtime"}
	}
	if active, _ := systemdActive("ufw"); active {
		return protocol.FirewallState{Type: "ufw", Backend: "ufw", Version: cmdVersion("ufw", "version"), Active: true, Mode: "runtime"}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return protocol.FirewallState{Type: "nftables", Backend: "nft", Version: cmdVersion("nft", "--version"), Active: true, Mode: "runtime"}
		}
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		if out, err := exec.Command("iptables-save").Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			return protocol.FirewallState{Type: "iptables-legacy", Backend: "iptables", Version: cmdVersion("iptables", "--version"), Active: true, Mode: "runtime"}
		}
	}
	return protocol.FirewallState{Type: "none", Active: false}
}

func systemdActive(name string) (bool, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, err
	}
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil, nil
}

func cmdVersion(bin string, arg string) string {
	out, err := exec.Command(bin, arg).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// --- helpers -------------------------------------------------------------

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "="); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.Trim(strings.TrimSpace(line[i+1:]), `"`)
		}
	}
	return m
}

func goArch() string {
	return archFromEnv()
}

func archFromEnv() string {
	a := os.Getenv("GOARCH")
	if a == "" {
		return "unknown"
	}
	return a
}

// cpuPercent samples /proc/stat over 200ms.
func cpuPercent() float64 {
	idle1, total1 := readCPU()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readCPU()
	if total2-total1 == 0 {
		return 0
	}
	idleDelta := idle2 - idle1
	totalDelta := total2 - total1
	busy := totalDelta - idleDelta
	return float64(busy) / float64(totalDelta) * 100
}

func readCPU() (idle, total float64) {
	f, err := os.Open("/proc/stat") // #nosec G304 -- fixed path
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		f := strings.Fields(sc.Text())
		// cpu user nice system idle iowait irq softirq steal
		if len(f) >= 5 && f[0] == "cpu" {
			var sum float64
			for _, x := range f[1:] {
				v, _ := strconv.ParseFloat(x, 64)
				sum += v
			}
			idle, _ = strconv.ParseFloat(f[4], 64)
			return idle, sum
		}
	}
	return 0, 0
}

func memPercent() float64 {
	b, err := os.ReadFile("/proc/meminfo") // #nosec G304 -- fixed path
	if err != nil {
		return 0
	}
	var total, avail float64
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt := strings.Fields(line)
			if len(fmt) > 1 {
				total, _ = strconv.ParseFloat(fmt[1], 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fmt := strings.Fields(line)
			if len(fmt) > 1 {
				avail, _ = strconv.ParseFloat(fmt[1], 64)
			}
		}
	}
	if total == 0 {
		return 0
	}
	return (total - avail) / total * 100
}
