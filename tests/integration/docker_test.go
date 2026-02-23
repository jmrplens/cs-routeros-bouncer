//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
)

func dockerAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("skipping: docker not available in PATH")
	}
	// Quick check that daemon is reachable.
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("skipping: docker daemon not reachable: %v\n%s", err, out)
	}
}

func TestDockerBuild(t *testing.T) {
	dockerAvailable(t)

	cmd := exec.Command("docker", "build",
		"-f", "docker/Dockerfile",
		"-t", "cs-routeros-bouncer:integration-test",
		".")
	cmd.Dir = "../.." // repo root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker build failed: %v\n%s", err, out)
	}
	t.Log("docker build succeeded")
}

func TestDockerVersion(t *testing.T) {
	dockerAvailable(t)

	// Ensure image exists (build it if a previous test built it).
	cmd := exec.Command("docker", "run", "--rm",
		"cs-routeros-bouncer:integration-test",
		"--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run --version failed: %v\n%s", err, out)
	}

	output := strings.TrimSpace(string(out))
	if !strings.Contains(output, "cs-routeros-bouncer") {
		t.Errorf("expected version output to contain 'cs-routeros-bouncer', got: %s", output)
	}
	t.Logf("version output: %s", output)
}

func TestDockerInvalidConfig(t *testing.T) {
	dockerAvailable(t)

	cmd := exec.Command("docker", "run", "--rm",
		"cs-routeros-bouncer:integration-test",
		"-c", "/nonexistent/config.yaml")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected docker run with invalid config to fail, but it succeeded")
	}

	output := string(out)
	t.Logf("expected error output: %s", strings.TrimSpace(output))
}
