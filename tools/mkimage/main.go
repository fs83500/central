// Command mkimage builds a Docker image archive WITHOUT a Docker daemon.
//
// The hub is a STATIC Go binary (CGO_ENABLED=0, pure-Go Postgres driver),
// so the image is `FROM scratch`: one layer with /app/hub (+ agent/fleet
// when given) and a /data mount point. The output is a docker-archive
// tarball that `docker load` / `podman load` import as-is — no daemon
// needed on the build machine (CI sandbox).
//
// Usage:
//
//	go run ./tools/mkimage -hub bin/hub -agent bin/agent -fleet bin/fleet \
//	    -tags central-unified:latest,central-unified:0.1 \
//	    -commit "$(git rev-parse --short HEAD)" -out central-unified.tar
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type dockerHealthcheck struct {
	Test     []string `json:"Test"`
	Interval string   `json:"Interval"`
	Timeout  string   `json:"Timeout"`
	Retries  int      `json:"Retries"`
}

type imageConfig struct {
	Env          []string            `json:"Env"`
	Entrypoint   []string            `json:"Entrypoint"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	Healthcheck  *dockerHealthcheck  `json:"Healthcheck,omitempty"`
}

type rootfsSpec struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type historySpec struct {
	Created   string `json:"created"`
	CreatedBy string `json:"created_by"`
}

type imageSpec struct {
	Created      string        `json:"created"`
	Author       string        `json:"author"`
	Architecture string        `json:"architecture"`
	OS           string        `json:"os"`
	Config       imageConfig   `json:"config"`
	RootFS       rootfsSpec    `json:"rootfs"`
	History      []historySpec `json:"history"`
}

type binaryEntry struct {
	path string
	dest string
}

func main() {
	var (
		hubPath    = flag.String("hub", "bin/hub", "hub binary (must be static: CGO_ENABLED=0)")
		agentPath  = flag.String("agent", "", "agent binary (optional, same image)")
		fleetPath  = flag.String("fleet", "", "fleet binary (optional, same image)")
		tagsFlag   = flag.String("tags", "central-unified:latest", "comma-separated RepoTags (name:tag)")
		commitFlag = flag.String("commit", "dev", "git commit for labels")
		outFlag    = flag.String("out", "central-unified.tar", "output docker-archive tar")
	)
	flag.Parse()

	tags := strings.Split(*tagsFlag, ",")
	for i := range tags {
		tags[i] = strings.TrimSpace(tags[i])
		if tags[i] == "" || strings.Count(tags[i], ":") != 1 {
			fmt.Fprintf(os.Stderr, "mkimage: invalid tag %q (expected name:tag)\n", tags[i])
			os.Exit(2)
		}
	}

	bins := []binaryEntry{{*hubPath, "app/hub"}}
	if *agentPath != "" {
		bins = append(bins, binaryEntry{*agentPath, "app/agent"})
	}
	if *fleetPath != "" {
		bins = append(bins, binaryEntry{*fleetPath, "app/fleet"})
	}

	if err := run(bins, tags, *commitFlag, *outFlag); err != nil {
		fmt.Fprintln(os.Stderr, "mkimage:", err)
		os.Exit(1)
	}
}

func run(bins []binaryEntry, tags []string, commit, out string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	layerBuf, err := buildLayer(bins)
	if err != nil {
		return fmt.Errorf("layer: %w", err)
	}
	diffSum := sha256.Sum256(layerBuf)
	diffID := "sha256:" + hex.EncodeToString(diffSum[:])

	spec := imageSpec{
		Created:      now,
		Author:       "UnifiedGuard daemonless build (tools/mkimage)",
		Architecture: "amd64",
		OS:           "linux",
		Config: imageConfig{
			Env: []string{
				"HUB_LISTEN=:8080",
				"HUB_MIGRATIONS=on",
				"HUB_MFA_LOG_BETA=1",
				"HUB_CA_DIR=/data/ca",
				"HUB_SITE_KEY_DIR=/data/sitekey",
			},
			Entrypoint: []string{"/app/hub"},
			WorkingDir: "/app",
			Labels: map[string]string{
				"org.opencontainers.image.title":       "central-unified",
				"org.opencontainers.image.description": "UnifiedGuard.cloud centrale (hub) — BETA",
				"org.opencontainers.image.version":     tags[0],
				"org.opencontainers.image.revision":    commit,
				"org.opencontainers.image.created":     now,
			},
			ExposedPorts: map[string]struct{}{"8080/tcp": {}},
			Volumes:      map[string]struct{}{"/data": {}},
			Healthcheck: &dockerHealthcheck{
				// FROM scratch: no curl — the hub ships its own probe.
				Test:     []string{"CMD", "/app/hub", "healthcheck"},
				Interval: "30s",
				Timeout:  "10s",
				Retries:  3,
			},
		},
		RootFS:  rootfsSpec{Type: "layers", DiffIDs: []string{diffID}},
		History: []historySpec{{Created: now, CreatedBy: "mkimage: static binaries + /data"}},
	}
	cfgBytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	cfgSum := sha256.Sum256(cfgBytes)
	cfgName := hex.EncodeToString(cfgSum[:]) + ".json"

	manifestBytes, err := json.MarshalIndent([]map[string]any{
		{
			"Config":   cfgName,
			"RepoTags": tags,
			"Layers":   []string{"layer.tar"},
		},
	}, "", "  ")
	if err != nil {
		return err
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	tw := tar.NewWriter(f)
	for _, ent := range []struct {
		name    string
		content []byte
	}{
		{cfgName, cfgBytes},
		{"manifest.json", manifestBytes},
		{"layer.tar", layerBuf},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     ent.name,
			Mode:     0o644,
			Size:     int64(len(ent.content)),
			ModTime:  time.Now(),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(ent.content); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}

	fi, _ := os.Stat(out)
	fmt.Printf("docker-archive ready: %s (%d bytes)\n", out, fi.Size())
	fmt.Printf("  RepoTags : %s\n", strings.Join(tags, ", "))
	fmt.Printf("  config   : %s\n", cfgName)
	fmt.Printf("  diff_id  : %s\n", diffID)
	fmt.Printf("  layer    : layer.tar (%d bytes)\n", len(layerBuf))
	fmt.Println("next: docker load -i " + out)
	return nil
}

// buildLayer assembles the uncompressed layer tar in memory: /app, /data
// and the static binaries (0755).
func buildLayer(bins []binaryEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	dirs := map[string]bool{"app": true, "data": true}
	for _, b := range bins {
		for d := parent(b.dest); d != ""; d = parent(d) {
			dirs[d] = true
		}
	}
	for name := range dirs {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: time.Now(),
		}); err != nil {
			return nil, err
		}
	}
	for _, b := range bins {
		data, err := os.ReadFile(b.path)
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: b.dest, Mode: 0o755,
			Size: int64(len(data)), ModTime: time.Now(),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parent(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i]
}
