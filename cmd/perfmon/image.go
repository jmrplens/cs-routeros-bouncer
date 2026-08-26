package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// buildSampler cross-compiles cmd/perfmon/sampler for the router. It needs
// nothing but the Go toolchain the developer is already running this tool
// with; the binary is static (CGO off) so a FROM-scratch image can carry it.
func buildSampler(goos, goarch string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "perfmon-sampler-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out := filepath.Join(dir, "sampler")
	// #nosec G204 -- the arguments are fixed except the temp output path this
	// function just created; the developer's own go toolchain is the point.
	cmd := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, "./cmd/perfmon/sampler") // NOSONAR --
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if outBytes, buildErr := cmd.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("go build sampler: %w\n%s", buildErr, outBytes)
	}
	return os.ReadFile(out) // #nosec G304 -- reading back the binary written two lines up
}

// imageTar packs the sampler binary into a docker-save-format tar that
// RouterOS's `/container add file=` accepts. Hand-crafted on purpose: needing
// a Docker daemon to install a monitoring probe would be the tool's heaviest
// dependency by far, and the format is three JSON files and one layer.
func imageTar(binary []byte, arch string) ([]byte, error) {
	// Layer: a tar holding /sampler.
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	if err := lw.WriteHeader(&tar.Header{
		Name: "sampler", Mode: 0o755, Size: int64(len(binary)),
		ModTime: time.Unix(0, 0), // deterministic: same binary, same image
	}); err != nil {
		return nil, err
	}
	if _, err := lw.Write(binary); err != nil {
		return nil, err
	}
	if err := lw.Close(); err != nil {
		return nil, err
	}
	layerDigest := sha256.Sum256(layer.Bytes())
	layerID := hex.EncodeToString(layerDigest[:])

	config, err := json.Marshal(map[string]any{
		"architecture": arch,
		"os":           "linux",
		"config":       map[string]any{"Entrypoint": []string{"/sampler"}},
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []string{"sha256:" + layerID},
		},
		// A fixed history entry keeps the image reproducible bit for bit.
		"history": []map[string]any{{"created": "1970-01-01T00:00:00Z", "created_by": "perfmon"}},
		"created": "1970-01-01T00:00:00Z",
	})
	if err != nil {
		return nil, err
	}
	configDigest := sha256.Sum256(config)
	configID := hex.EncodeToString(configDigest[:])

	manifest, err := json.Marshal([]map[string]any{{
		"Config":   configID + ".json",
		"RepoTags": []string{"perfmon/cpuhr01:local"},
		"Layers":   []string{layerID + "/layer.tar"},
	}})
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	files := []struct {
		name string
		data []byte
	}{
		{configID + ".json", config},
		{layerID + "/layer.tar", layer.Bytes()},
		{"manifest.json", manifest},
	}
	for _, f := range files {
		if hdrErr := tw.WriteHeader(&tar.Header{
			Name: f.name, Mode: 0o644, Size: int64(len(f.data)), ModTime: time.Unix(0, 0),
		}); hdrErr != nil {
			return nil, hdrErr
		}
		if _, writeErr := tw.Write(f.data); writeErr != nil {
			return nil, writeErr
		}
	}
	if closeErr := tw.Close(); closeErr != nil {
		return nil, closeErr
	}
	return out.Bytes(), nil
}
