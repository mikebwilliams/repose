package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func auditFixture(t *testing.T, extraFiles ...int) (*GitRepository, *inventoryStore, auditScan, []auditTaskInput) {
	t.Helper()
	ctx := context.Background()
	repository, directory := newInventoryFixture(t)
	if len(extraFiles) > 0 {
		for i := range extraFiles[0] {
			writeInventoryFixtureFile(t, filepath.Join(directory, "pcbnew", fmt.Sprintf("batch_%03d.cpp", i)), []byte(fmt.Sprintf("int batch_%d() { return %d; }\n", i, i)))
		}
		testGit(t, directory, "add", "pcbnew")
		testGit(t, directory, "commit", "-m", "batch fixture")
	}
	record := runReposeRecord(t, directory, "inventory", "build")
	database, err := reposeDatabasePath(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openInventoryStore(ctx, database, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err = store.MarkInventoryReviewed(ctx, record.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	record, err = store.Inventory(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planInventory(record, inventorySelection{Path: "pcbnew", Status: "included"}, "Check lifetime.", inventoryPlanLimits{1, 65536})
	if err != nil {
		t.Fatal(err)
	}
	spec := auditSpec{Plan: plan, Model: auditModelConfig{Harness: "codex", Model: "test-model", Effort: "high", Binary: testTrueBinary, Timeout: time.Second}, PromptVersion: auditPromptVersion, Instructions: "Inspect ownership."}
	inputs, err := prepareAuditInputs(ctx, record, spec)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := store.createAudit(ctx, record, spec, inputs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return repository, store, scan, inputs
}

func auditTestResponse(input auditTaskInput) auditInvocation {
	target := input.Targets[0]
	output := auditOutput{Status: "completed", Summary: "Assessed assigned source.", Findings: []NewFinding{{Severity: "warning", Title: "Fixture finding", Description: "A fixture finding for lifecycle verification.", File: stringPointer(target.Path), Line: &target.StartLine}}}
	data, _ := json.Marshal(output)
	return auditInvocation{StructuredOutput: string(data), RawResponse: "retained transcript", Usage: &TokenUsage{InputTokens: 12, OutputTokens: 3}}
}

func auditTestRunner(inputs []auditTaskInput) auditRunner {
	return func(_ context.Context, _ auditModelConfig, prompt string) (auditInvocation, error) {
		for _, input := range inputs {
			if input.Prompt == prompt {
				return auditTestResponse(input), nil
			}
		}
		return auditInvocation{}, errors.New("unexpected prompt")
	}
}

func TestAuditParallelLimitResumeAndFrozenInputs(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	finished := make(chan error, 1)
	var active, peak atomic.Int32
	runner := func(ctx context.Context, c auditModelConfig, prompt string) (auditInvocation, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return auditInvocation{}, ctx.Err()
		}
		return auditTestRunner(inputs)(ctx, c, prompt)
	}
	go func() {
		finished <- runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2, Limit: 2}, runner, io.Discard)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("workers did not run concurrently")
		}
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	updated, err := store.audit(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 2 || updated.Counts["completed"] != 2 || updated.Counts["pending"] != 1 || updated.Status != "paused" {
		t.Fatalf("incorrect limited run: %+v peak %d", updated.Counts, peak.Load())
	}
	// Policy changes and later questions cannot change this scan's prompts/scope.
	record, err := store.Inventory(ctx, "current")
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := editInventoryScope(record.Inventory, []string{"pcbnew/main.cpp"}, true, "next scan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.saveCurrentInventory(ctx, changed, &record.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	tasks, err := store.auditTasks(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, task := range tasks {
		if task.Input.Prompt != inputs[i].Prompt {
			t.Fatal("frozen prompt changed")
		}
	}
	if err = runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatalf("completed tasks rerun: %d %v", len(attempts), err)
	}
	if err = runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	attempts, _ = store.auditAttempts(ctx, scan.ID)
	if len(attempts) != 3 {
		t.Fatal("repeat resume dispatched completed work")
	}
}

func TestAuditInterruptRecoveryAndStalePublication(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	started := make(chan struct{}, 2)
	canceled, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	runner := func(ctx context.Context, _ auditModelConfig, _ string) (auditInvocation, error) {
		started <- struct{}{}
		<-ctx.Done()
		return auditInvocation{RawResponse: "interrupted transcript"}, ctx.Err()
	}
	go func() { done <- runAudit(canceled, store, repo, scan, auditRunOptions{Jobs: 2}, runner, io.Discard) }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("runner did not start")
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	attempts, _ := store.auditAttempts(ctx, scan.ID)
	if len(attempts) != 2 {
		t.Fatal("interrupted attempts lost")
	}
	for _, a := range attempts {
		if a.Status != "interrupted" || a.Invocation.RawResponse != "interrupted transcript" {
			t.Fatalf("lost interruption: %+v", a)
		}
	}
	// Simulate coordinator death after claiming, then reject a late old result.
	old, err := store.claimAuditTask(ctx, scan.ID, scan.Spec.Model.Timeout, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.recoverAudit(ctx, scan, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	current, err := store.claimAuditTask(ctx, scan.ID, scan.Spec.Model.Timeout, time.Now())
	if err != nil || current.ID != old.ID || current.AttemptID == old.AttemptID {
		t.Fatal("recovery did not supersede abandoned claim")
	}
	output, err := parseAuditOutput([]byte(auditTestResponse(inputs[0]).StructuredOutput), inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = store.finishAuditTask(ctx, scan, *old, "completed", auditTestResponse(inputs[0]), &output, nil, time.Now()); !errors.Is(err, errAuditStaleAttempt) {
		t.Fatalf("old attempt published: %v", err)
	}
	if err = store.finishAuditTask(ctx, scan, *current, "completed", auditTestResponse(inputs[0]), &output, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = store.finishAuditTask(ctx, scan, *current, "completed", auditTestResponse(inputs[0]), &output, nil, time.Now()); !errors.Is(err, errAuditStaleAttempt) {
		t.Fatal("duplicate completion published")
	}
	if err = runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = store.db.QueryRow("SELECT count(*) FROM audit_findings WHERE scan_id=?", scan.ID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("findings duplicated: %d %v", count, err)
	}
}

func TestAuditMalformedResponseAndExplicitRetry(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	broken := func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		return auditInvocation{StructuredOutput: "not JSON", RawResponse: "complete malformed transcript", Stderr: "stderr detail"}, nil
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1, Limit: 1}, broken, io.Discard); err == nil {
		t.Fatal("malformed response counted as success")
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "failed" || attempts[0].Invocation.StructuredOutput != "not JSON" || attempts[0].Invocation.Stderr != "stderr detail" {
		t.Fatalf("malformed output lost: %+v %v", attempts, err)
	}
	if err = runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2, RetryFailed: true}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	attempts, _ = store.auditAttempts(ctx, scan.ID)
	if len(attempts) != 4 {
		t.Fatal("retry did not retain failed attempt")
	}
	if _, err = parseAuditOutput([]byte(`{"status":"completed","summary":"ok","findings":[{"severity":"warning","title":"x","description":"x","file":"thirdparty/vendor.cpp","line":1,"symbol":null}]}`), inputs[0]); err == nil {
		t.Fatal("out-of-scope finding accepted")
	}
	if _, err = parseAuditOutput([]byte(`{"status":"completed","summary":"ok"}`), inputs[0]); err == nil {
		t.Fatal("absent findings accepted as coverage")
	}
}

func TestAuditPauseDrainsAndSnapshotChangeStopsDispatch(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	runner := func(ctx context.Context, c auditModelConfig, p string) (auditInvocation, error) {
		started <- struct{}{}
		<-release
		return auditTestRunner(inputs)(ctx, c, p)
	}
	go func() { done <- runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1}, runner, io.Discard) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("no running task")
	}
	if _, err := store.db.Exec("UPDATE audit_scans SET control='pause' WHERE id=?", scan.ID); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	updated, _ := store.audit(ctx, scan.ID)
	if updated.Counts["completed"] != 1 || updated.Counts["pending"] != 2 {
		t.Fatalf("pause dispatched extra work: %+v", updated.Counts)
	}
	filename := filepath.Join(repo.WorkTree, "pcbnew/main.cpp")
	if err := os.WriteFile(filename, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1}, auditTestRunner(inputs), io.Discard); err == nil {
		t.Fatal("changed checkout accepted")
	}
	attempts, _ := store.auditAttempts(ctx, scan.ID)
	if len(attempts) != 1 {
		t.Fatal("stale checkout dispatched work")
	}
}

func TestAuditFindingsTUILifecycleAndSnapshotPreview(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1, Limit: 1}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	database, _ := reposeDatabasePath(ctx, repo)
	backend := &auditFindingStore{reader: store, databasePath: database, scanID: scan.ID}
	findings, err := backend.AllFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %v %v", findings, err)
	}
	f := findings[0]
	if f.IntroducedSHA != "" || f.ObservedSHA != scan.Spec.Plan.SnapshotSHA || f.AttemptID == 0 || f.ScanID != scan.ID {
		t.Fatal("observed provenance missing")
	}
	preview, err := loadAuditFindingPreview(ctx, repo, f)
	if err != nil || !strings.Contains(strings.Join(preview.Lines, "\n"), "main.h") {
		t.Fatalf("snapshot preview: %+v %v", preview, err)
	}
	m := newFindingsModel(ctx, findingExternalCommands{snapshot: true}, backend, findings, auditFindingDisplay(findings), true, time.Now)
	if view := m.View().Content; !strings.Contains(view, "Repose findings") || strings.Contains(view, "Introduced:") {
		t.Fatal("AIR attribution leaked into Repose")
	}
	m.input = "test dismissal"
	m.dismissSelected()
	found, _ := backend.AllFindings(ctx)
	if found[0].DismissedAt == nil {
		t.Fatal("TUI dismissal did not persist")
	}
	m.input = "audited note"
	m.noteSelected()
	m.reopenSelected()
	found, _ = backend.AllFindings(ctx)
	events, _ := backend.FindingEvents(ctx, f.ID)
	if found[0].DismissedAt != nil || len(events) != 4 {
		t.Fatalf("lifecycle lost: %+v %+v", found, events)
	}
	var output bytes.Buffer
	if err := runReposeCLI(ctx, []string{"findings", "--repo", repo.WorkTree, "--scan", scan.ID, "--json"}, cliEnvironment{Cwd: repo.WorkTree, Stdout: &output, Stderr: &output}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "introduced_sha") || !strings.Contains(output.String(), "observed_sha") {
		t.Fatal("JSON used introducing-commit attribution")
	}
}

func TestAuditCodexCaptureAndCancellation(t *testing.T) {
	repo, _, scan, inputs := auditFixture(t)
	config := scan.Spec.Model
	config.Binary = "fake-codex"
	command := func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		var output string
		for i, arg := range args {
			if arg == "--output-last-message" {
				output = args[i+1]
			}
		}
		if !strings.Contains(strings.Join(args, " "), "--sandbox read-only") || !strings.Contains(strings.Join(args, " "), "--output-schema") {
			t.Error("missing subprocess restrictions or schema")
		}
		return exec.CommandContext(ctx, "sh", "-c", `cat >/dev/null; printf '%s' "$1" > "$2"; printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}'; printf 'diagnostic' >&2`, "fixture", auditTestResponse(inputs[0]).StructuredOutput, output)
	}
	result, err := invokeAuditCodex(context.Background(), repo, config, inputs[0].Prompt, command)
	if err != nil || result.Usage == nil || result.Usage.InputTokens != 10 || result.Stderr != "diagnostic" {
		t.Fatalf("capture: %+v %v", result, err)
	}
	config.Timeout = 100 * time.Millisecond
	command = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'partial transcript'; sleep 30")
	}
	start := time.Now()
	result, err = invokeAuditCodex(context.Background(), repo, config, "prompt", command)
	if err == nil || time.Since(start) > 3*time.Second || result.RawResponse != "partial transcript" {
		t.Fatalf("cancellation failed: %+v %v", result, err)
	}
}

func TestAuditCLIWorkflowAndUnableCoverage(t *testing.T) {
	repository, directory := newInventoryFixture(t)
	record := runReposeRecord(t, directory, "inventory", "build")
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	environment := cliEnvironment{Cwd: directory, Stdout: &stdout, Stderr: &stderr}
	args := []string{"scan", "create", "--model", "fixture-model", "--binary", testTrueBinary, "--path", "pcbnew", "--max-files", "1", "--json"}
	if err := runReposeCLI(ctx, args, environment); err == nil {
		t.Fatal("unapproved inventory accepted")
	}
	if _, err := executeReposeTest(t, directory, "inventory", "approve", record.ID); err != nil {
		t.Fatal(err)
	}
	if err := runReposeCLI(ctx, args, environment); err != nil {
		t.Fatal(err)
	}
	var scan auditScan
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatal(err)
	}
	if scan.Counts["pending"] != 3 || scan.Spec.Model.Model != "fixture-model" || scan.Spec.Model.Timeout != 30*time.Minute {
		t.Fatalf("create did not freeze configuration: %+v", scan)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"scan", "prompt", scan.ID, "1"}, environment); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Review the assigned target ranges") || !strings.Contains(stdout.String(), "int main()") {
		t.Fatal("frozen prompt missing source or assignment protocol")
	}
	stdout.Reset()
	environment.AuditRunner = func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		return auditInvocation{StructuredOutput: `{"status":"unable_to_assess","summary":"Fixture missing context.","findings":[]}`}, nil
	}
	if err := runReposeCLI(ctx, []string{"scan", "run", scan.ID, "--jobs", "2", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var updated auditScan
	if err := json.Unmarshal(stdout.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status != "incomplete" || updated.Counts["unable_to_assess"] != 3 || updated.Counts["completed"] != 0 {
		t.Fatalf("unable counted as coverage: %+v", updated.Counts)
	}
	for _, command := range []string{"show", "tasks", "attempts"} {
		stdout.Reset()
		if err := runReposeCLI(ctx, []string{"scan", command, scan.ID, "--json"}, environment); err != nil || !json.Valid(stdout.Bytes()) {
			t.Fatalf("%s: %v %s", command, err, stdout.String())
		}
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"scan", "list", "--json"}, environment); err != nil || !json.Valid(stdout.Bytes()) {
		t.Fatalf("list: %v", err)
	}
	for _, bad := range [][]string{{"scan", "run", scan.ID, "--jobs", "0"}, {"scan", "run", scan.ID, "--limit", "-1"}, {"scan", "run", scan.ID, "--model", "other"}, {"scan", "prompt", scan.ID, "absent"}} {
		if err := runReposeCLI(ctx, bad, environment); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	database, _ := reposeDatabasePath(ctx, repository)
	store, err := openInventoryReadOnly(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatal("inspection dispatched model work")
	}
}

func TestAuditCoordinatorLockAndOtherRunnerFailureCapture(t *testing.T) {
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	database, _ := reposeDatabasePath(ctx, repo)
	lock, err := acquireScanLock(filepath.Join(filepath.Dir(database), "scan.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err = runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1}, auditTestRunner(inputs), io.Discard); err == nil {
		lock.Close()
		t.Fatal("second coordinator acquired live lock")
	}
	lock.Close()
	command := func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'raw failure'; printf 'provider error' >&2; exit 1")
	}
	runner := newAuditRunner(repo, cliEnvironment{ClaudeCommand: command, GeminiCommand: command})
	for _, harness := range []string{"claude", "gemini"} {
		config := scan.Spec.Model
		config.Harness = harness
		if harness == "gemini" {
			config.Effort = "default"
		}
		result, err := runner(ctx, config, "fixture prompt")
		if err == nil || result.RawResponse != "raw failure" || result.Stderr != "provider error" || result.Usage != nil {
			t.Fatalf("%s lost failed capture: %+v %v", harness, result, err)
		}
	}
}
