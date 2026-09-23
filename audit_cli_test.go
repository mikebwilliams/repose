package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuditCLIResumeSelectsOnlyResumableScan(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	record, err := store.Inventory(ctx, scan.Spec.Plan.InventoryID)
	if err != nil {
		t.Fatal(err)
	}
	var failedID string
	for _, state := range []struct{ scan, task string }{
		{"completed", "completed"},
		{"invalid", "pending"},
		{"incomplete", "unable_to_assess"},
		{"incomplete", "failed"},
	} {
		other, err := store.createAudit(ctx, record, scan.Spec, inputs, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.db.ExecContext(ctx, "UPDATE audit_scans SET status=? WHERE id=?", state.scan, other.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = store.db.ExecContext(ctx, "UPDATE audit_tasks SET status=? WHERE scan_id=?", state.task, other.ID); err != nil {
			t.Fatal(err)
		}
		if state.task == "failed" {
			failedID = other.ID
		}
	}
	var stdout, stderr bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: &stderr, AuditRunner: func(ctx context.Context, config auditModelConfig, prompt string) (auditInvocation, error) {
		calls.Add(1)
		return auditTestRunner(inputs)(ctx, config, prompt)
	}}
	// The selected pending scan is older than all the ineligible alternatives.
	args := []string{"scan", "resume", "--jobs", "2", "--limit", "1", "--json"}
	if err := runReposeCLI(ctx, args, env); err != nil {
		t.Fatal(err)
	}
	var updated auditScan
	if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != scan.ID || updated.Status != "paused" || updated.Counts["completed"] != 1 || updated.Counts["pending"] != 2 || !strings.Contains(stderr.String(), scan.ID[:12]) {
		t.Fatalf("wrong selection or ignored dispatch limit: %+v; stderr=%s", updated, stderr.String())
	}
	// Automatic selection also resumes a paused scan and preserves completed work.
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"scan", "resume", "--json"}, env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != scan.ID || updated.Status != "completed" || calls.Load() != 3 {
		t.Fatalf("resume repeated completed work: scan=%+v calls=%d", updated, calls.Load())
	}
	stdout.Reset()
	err = runReposeCLI(ctx, []string{"scan", "resume", "--json"}, env)
	if err == nil || !strings.Contains(err.Error(), "no scans have resumable work") || !strings.Contains(err.Error(), "--retry-failed") || calls.Load() != 3 || stdout.Len() != 0 {
		t.Fatalf("no eligible scans should not dispatch: err=%v calls=%d stdout=%s", err, calls.Load(), stdout.String())
	}
	if err := runReposeCLI(ctx, []string{"scan", "resume", "--retry-failed", "--json"}, env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != failedID || updated.Status != "completed" || calls.Load() != 6 {
		t.Fatalf("--retry-failed did not select failed work: scan=%+v calls=%d", updated, calls.Load())
	}
}

func TestAuditCLIResumeAmbiguityRequiresID(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	record, err := store.Inventory(ctx, scan.Spec.Plan.InventoryID)
	if err != nil {
		t.Fatal(err)
	}
	spec := scan.Spec
	spec.Model.Model = "second-model"
	other, err := store.createAudit(ctx, record, spec, inputs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: &stderr, AuditRunner: func(ctx context.Context, config auditModelConfig, prompt string) (auditInvocation, error) {
		calls.Add(1)
		return auditTestRunner(inputs)(ctx, config, prompt)
	}}
	err = runReposeCLI(ctx, []string{"scan", "resume", "--json"}, env)
	if err == nil || !strings.Contains(err.Error(), "multiple scans") || calls.Load() != 0 || stdout.Len() != 0 {
		t.Fatalf("ambiguous resume dispatched or produced success JSON: %v calls=%d stdout=%s", err, calls.Load(), stdout.String())
	}
	for _, candidate := range []auditScan{scan, other} {
		if !strings.Contains(stderr.String(), candidate.ID[:12]) || !strings.Contains(stderr.String(), candidate.Spec.Model.Model) {
			t.Fatalf("candidate missing from choices: %s", stderr.String())
		}
		updated, err := store.audit(ctx, candidate.ID)
		if err != nil || updated.Status != "pending" || updated.Counts["pending"] != 3 {
			t.Fatalf("ambiguous selection changed scan state: %+v %v", updated, err)
		}
	}
	// Explicit prefixes still resolve ambiguity; run still requires an ID.
	for _, args := range [][]string{{"scan", "run"}, {"scan", "resume", scan.ID, other.ID}} {
		if err := runReposeCLI(ctx, args, env); err == nil || calls.Load() != 0 {
			t.Fatalf("invalid arguments dispatched work: %v err=%v", args, err)
		}
	}
	if err := runReposeCLI(ctx, []string{"scan", "resume", scan.ID[:12], "--limit", "1", "--json"}, env); err != nil {
		t.Fatal(err)
	}
	var updated auditScan
	if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ID != scan.ID || updated.Counts["completed"] != 1 || calls.Load() != 1 {
		t.Fatal("explicit resume selected the wrong scan")
	}
}

func TestAuditCLIResumeSelectsAbandonedScan(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	if err := store.recoverAudit(ctx, scan, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Leave all tasks running, as if the coordinator had crashed.
	for range inputs {
		if task, err := store.claimAuditTask(ctx, scan.ID, 5*time.Minute, time.Now()); err != nil || task == nil {
			t.Fatalf("claim: %v %v", task, err)
		}
	}
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: io.Discard, Stderr: io.Discard, AuditRunner: auditTestRunner(inputs)}
	if err := runReposeCLI(ctx, []string{"scan", "resume", "--timeout", "10m"}, env); err != nil {
		t.Fatal(err)
	}
	updated, err := store.audit(ctx, scan.ID)
	if err != nil || updated.Status != "completed" || updated.Counts["completed"] != 3 {
		t.Fatalf("abandoned scan was not recovered: %+v %v", updated, err)
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 6 || attempts[0].Status != "interrupted" {
		t.Fatalf("abandoned attempt history lost: %d attempts, %v", len(attempts), err)
	}
	for i, attempt := range attempts {
		want := 5 * time.Minute
		if i >= 3 {
			want = 10 * time.Minute
		}
		if attempt.Timeout != want {
			t.Fatalf("recovery changed an attempt's timeout: %+v; want %s", attempt, want)
		}
	}
}

func TestAuditCLIResumeNoScans(t *testing.T) {
	_, directory := newInventoryFixture(t)
	runReposeRecord(t, directory, "inventory", "build")
	env := cliEnvironment{Cwd: directory, Stdout: io.Discard, Stderr: io.Discard, AuditRunner: func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		t.Fatal("resume without scans dispatched work")
		return auditInvocation{}, nil
	}}
	err := runReposeCLI(context.Background(), []string{"scan", "resume"}, env)
	if err == nil || !strings.Contains(err.Error(), "no scans have resumable work") {
		t.Fatalf("missing no-scans diagnostic: %v", err)
	}
}

func TestAuditCLITimeoutOverrideAndRetryHistory(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	originalSpec, err := json.Marshal(scan.Spec)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: &stderr}
	steps := []struct {
		args    []string
		timeout time.Duration
		fails   bool
	}{
		{[]string{"scan", "run", scan.ID, "--jobs", "1", "--limit", "1", "--json"}, scan.Spec.Model.Timeout, false},
		{[]string{"scan", "run", scan.ID, "--jobs", "1", "--limit", "1", "--timeout", "200ms", "--json"}, 200 * time.Millisecond, true},
		{[]string{"scan", "resume", "--retry-failed", "--jobs", "1", "--limit", "1", "--timeout", "30m", "--json"}, 30 * time.Minute, false},
		{[]string{"scan", "resume", "--jobs", "1", "--limit", "1", "--json"}, scan.Spec.Model.Timeout, false},
	}
	for i, step := range steps {
		timeouts := make(chan time.Duration, 1)
		env.AuditRunner = func(ctx context.Context, config auditModelConfig, prompt string) (auditInvocation, error) {
			timeouts <- config.Timeout
			// The timeout must already be durable while the assignment is running.
			attempts, err := store.auditAttempts(ctx, scan.ID)
			if err != nil {
				return auditInvocation{}, err
			}
			if len(attempts) != i+1 || attempts[i].Status != "running" || attempts[i].Timeout != step.timeout {
				t.Errorf("timeout not recorded before dispatch: %+v", attempts)
			}
			if step.fails {
				return invokeAuditCodex(ctx, repo, config, prompt, func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
					return exec.CommandContext(ctx, "sh", "-c", "printf 'timeout fixture'; sleep 30")
				})
			}
			return auditTestRunner(inputs)(ctx, config, prompt)
		}
		stdout.Reset()
		stderr.Reset()
		err := runReposeCLI(ctx, step.args, env)
		if (err != nil) != step.fails || (step.fails && !strings.Contains(stderr.String(), "Codex timed out after 200ms")) {
			t.Fatalf("step %d: err=%v stderr=%s", i, err, stderr.String())
		}
		select {
		case got := <-timeouts:
			if got != step.timeout {
				t.Fatalf("runner received timeout %s; want %s", got, step.timeout)
			}
		default:
			t.Fatal("assignment was not dispatched")
		}
		var updated auditScan
		if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
			t.Fatal(err)
		}
		updatedSpec, err := json.Marshal(updated.Spec)
		if err != nil || !bytes.Equal(originalSpec, updatedSpec) {
			t.Fatal("timeout override changed the frozen scan")
		}
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 4 {
		t.Fatalf("unexpected attempt history: %+v %v", attempts, err)
	}
	for i, attempt := range attempts {
		if attempt.Timeout != steps[i].timeout {
			t.Fatalf("effective timeout lost: %+v", attempt)
		}
	}
	if attempts[1].Status != "failed" || attempts[1].Invocation.RawResponse != "timeout fixture" || attempts[1].TaskID != attempts[2].TaskID || attempts[2].Number != 2 {
		t.Fatalf("retry lost the timeout failure or selected another assignment: %+v", attempts)
	}
	updated, err := store.audit(ctx, scan.ID)
	if err != nil || updated.Status != "completed" || updated.Counts["completed"] != 3 {
		t.Fatalf("retry did not complete the remaining work: %+v %v", updated, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"scan", "attempts", scan.ID}, env); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "timeout=200ms") || !strings.Contains(stdout.String(), "timeout=30m0s") {
		t.Fatalf("effective timeout missing from CLI history: %s", stdout.String())
	}
}

func TestAuditCLIRejectsInvalidTimeouts(t *testing.T) {
	repo, store, scan, _ := auditFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: io.Discard, Stderr: io.Discard, AuditRunner: func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		calls.Add(1)
		return auditInvocation{}, nil
	}}
	for _, args := range [][]string{{"scan", "create", "--model", "test-model", "--binary", testTrueBinary}, {"scan", "run", scan.ID}, {"scan", "resume"}} {
		for _, timeout := range []string{"0", "-1s", "invalid"} {
			command := append(append([]string{}, args...), "--timeout", timeout)
			if err := runReposeCLI(ctx, command, env); err == nil {
				t.Fatalf("accepted invalid timeout: %v", command)
			}
		}
	}
	updated, err := store.audit(ctx, scan.ID)
	if err != nil || calls.Load() != 0 || updated.Status != "pending" {
		t.Fatalf("invalid timeout started work: calls=%d scan=%+v err=%v", calls.Load(), updated, err)
	}
}
