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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func auditRecheckFixture(t *testing.T, counts ...int) (*GitRepository, *inventoryStore, auditScan, []Finding) {
	t.Helper()
	repo, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	runner := auditTestRunner(inputs)
	if len(counts) > 0 {
		if len(counts) != len(inputs) {
			t.Fatal("fixture requires a finding count for each source assignment")
		}
		runner = func(_ context.Context, _ auditModelConfig, prompt string) (auditInvocation, error) {
			for i, input := range inputs {
				if input.Prompt != prompt {
					continue
				}
				invocation := auditTestResponse(input)
				var output auditOutput
				if err := json.Unmarshal([]byte(invocation.StructuredOutput), &output); err != nil {
					return auditInvocation{}, err
				}
				finding := output.Findings[0]
				output.Findings = []NewFinding{}
				for j := range counts[i] {
					finding.Title = fmt.Sprintf("Claim %d from source assignment %d", j+1, i+1)
					output.Findings = append(output.Findings, finding)
				}
				raw, err := json.Marshal(output)
				invocation.StructuredOutput = string(raw)
				return invocation, err
			}
			return auditInvocation{}, errors.New("unexpected prompt")
		}
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1}, runner, io.Discard); err != nil {
		t.Fatal(err)
	}
	scan, err := store.audit(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	findingStore := &auditFindingStore{reader: store, scanID: scan.ID}
	findings, err := findingStore.AllFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return repo, store, scan, findings
}

func auditRecheckTestRunner(ctx context.Context, config auditModelConfig, prompt string) (auditInvocation, error) {
	marker := "Assignment data (line numbers are one-based, byte ranges end-exclusive):\n"
	_, data, ok := strings.Cut(prompt, marker)
	if !ok {
		return auditInvocation{}, errors.New("no frozen assignment data")
	}
	var input struct {
		Finding  auditRecheckFinding   `json:"finding"`
		Findings []auditRecheckFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(data), &input); err != nil {
		return auditInvocation{}, err
	}
	group := input.Findings
	if group == nil {
		group = []auditRecheckFinding{input.Finding}
	}
	results := []auditRecheckOutput{}
	for _, f := range group {
		if f.ID <= 0 || f.Snapshot == "" || f.Claim.Description == "" {
			return auditInvocation{}, errors.New("missing frozen claim")
		}
		outcome := []string{"confirmed", "false_positive", "uncertain"}[(f.ID-1)%3]
		results = append(results, auditRecheckOutput{FindingID: f.ID, Outcome: outcome, Reason: "Independent evidence in pcbnew/main.cpp:1; tested claim and caller guards."})
	}
	var output any = auditRecheckBatchOutput{Results: results}
	if input.Findings == nil {
		output = results[0]
	}
	raw, err := json.Marshal(output)
	return auditInvocation{StructuredOutput: string(raw), RawResponse: "verification transcript"}, err
}

func TestAuditRecheckWorkflowResumeAndHistory(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	record, err := store.Inventory(ctx, source.Spec.Plan.InventoryID)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := prepareAuditInputs(ctx, record, source.Spec)
	if err != nil {
		t.Fatal(err)
	}
	// A newer, unstarted review must not replace the completed source scan.
	if _, err := store.createAudit(ctx, record, source.Spec, inputs, time.Now()); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: &stderr, AuditRunner: func(ctx context.Context, c auditModelConfig, p string) (auditInvocation, error) {
		calls.Add(1)
		if c.Model != "verifier" || c.Effort != "xhigh" {
			t.Errorf("wrong verification model: %+v", c)
		}
		return auditRecheckTestRunner(ctx, c, p)
	}}
	args := []string{"recheck", "--model", "verifier", "--binary", testTrueBinary, "--effort", "xhigh", "--jobs", "2", "--limit", "2", "--json"}
	invoke := func(args []string) auditScan {
		t.Helper()
		stdout.Reset()
		if err := runReposeCLI(ctx, args, env); err != nil {
			t.Fatal(err)
		}
		var scan auditScan
		if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
			t.Fatal(err)
		}
		return scan
	}
	first := invoke(args)
	if first.Spec.Recheck.SourceScanID != source.ID || first.Status != "paused" || first.Counts["completed"] != 2 || first.Counts["pending"] != 1 || calls.Load() != 2 {
		t.Fatalf("wrong limited recheck: %+v", first)
	}
	resumed := invoke(append(append([]string{}, args...), "--timeout", "1h"))
	if resumed.ID != first.ID || resumed.Status != "completed" || calls.Load() != 3 || resumed.Verdicts["confirmed"] != 1 || resumed.Verdicts["false_positive"] != 1 || resumed.Verdicts["uncertain"] != 1 {
		t.Fatalf("resume lost results or changed identity: %+v", resumed)
	}
	if again := invoke(args); again.ID != first.ID || calls.Load() != 3 {
		t.Fatal("repeating recheck reran completed work or selected a recheck as its source")
	}
	attempts, err := store.auditAttempts(ctx, first.ID)
	if err != nil || len(attempts) != 3 || attempts[2].Timeout != time.Hour || len(attempts[0].Output.RecheckBatch) != 1 {
		t.Fatalf("recheck attempts lost: %+v %v", attempts, err)
	}
	database, _ := reposeDatabasePath(ctx, repo)
	fs := &auditFindingStore{reader: store, databasePath: database, scanID: source.ID}
	verified, err := fs.AllFindings(ctx)
	if err != nil || len(verified) != len(findings) {
		t.Fatalf("recheck created new findings: %d %v", len(verified), err)
	}
	for i, f := range verified {
		if f.Description != findings[i].Description || f.DismissedAt != nil || len(f.Verifications) != 1 || f.Verifications[0].Model != "verifier" || f.Verifications[0].Snapshot != f.ObservedSHA {
			t.Fatalf("original finding changed or verification missing: %+v", f)
		}
		events, err := fs.FindingEvents(ctx, f.ID)
		if err != nil || len(events) != 2 || events[1].Action != "rechecked" {
			t.Fatalf("verification history missing: %+v %v", events, err)
		}
	}
	// Completion publication is guarded by the same attempt ownership as scans.
	tasks, _ := store.auditTasks(ctx, first.ID)
	if err := store.finishAuditTask(ctx, first, tasks[0], "completed", attempts[0].Invocation, attempts[0].Output, nil, time.Now()); !errors.Is(err, errAuditStaleAttempt) {
		t.Fatalf("duplicate recheck publication accepted: %v", err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"findings", "--scan", source.ID, "--verification", "false_positive", "--json"}, env); err != nil {
		t.Fatal(err)
	}
	var filtered []Finding
	if err := json.Unmarshal(stdout.Bytes(), &filtered); err != nil || len(filtered) != 1 || auditVerificationOutcome(filtered[0]) != "false_positive" {
		t.Fatalf("verdict filter: %s %v", stdout.String(), err)
	}
	model := newFindingsModel(ctx, findingExternalCommands{snapshot: true}, fs, verified, auditFindingDisplay(verified), false, time.Now)
	model.verificationFilter = "confirmed"
	model.applyFilters(0)
	if len(model.visible) != 1 || !strings.Contains(strings.Join(model.detailLines(100), "\n"), "Latest verification: confirmed") {
		t.Fatal("TUI does not show/filter verification")
	}
	// A fresh pass retains previous opinions and manual dispositions.
	otherModel := invoke(append(append([]string{}, args...), "--model", "second-verifier", "--create-only"))
	if otherModel.ID == first.ID || otherModel.Spec.Model.Model != "second-verifier" || otherModel.Counts["pending"] != 3 {
		t.Fatal("different model reused another model's verification pass")
	}
	forced := invoke(append(append([]string{}, args...), "--force", "--create-only"))
	if forced.ID == first.ID || forced.Counts["pending"] != 3 {
		t.Fatal("force did not create a separate verification pass")
	}
	if err := fs.DismissFinding(ctx, findings[0].ID, "human disposition", time.Now()); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"scan", "resume", forced.ID, "--limit", "1"}, env); err != nil {
		t.Fatal(err)
	}
	verified, err = fs.AllFindings(ctx)
	if err != nil || len(verified[0].Verifications) != 2 || verified[0].DismissReason != "human disposition" {
		t.Fatal("verification overwrote a human disposition or its earlier opinion")
	}
	sourceAfter, _ := store.audit(ctx, source.ID)
	if sourceAfter.Status != "completed" || sourceAfter.Counts["completed"] != 3 {
		t.Fatal("recheck modified the original scan")
	}
}

func TestAuditRecheckQuotaFailureAndExplicitRetry(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	record, _ := store.Inventory(ctx, source.Spec.Plan.InventoryID)
	spec, err := buildAuditRecheckSpec(source, findings, source.Spec.Model, defaultAuditRecheckBatchMax)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := prepareAuditInputs(ctx, record, spec)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := store.createAudit(ctx, record, spec, inputs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	quota := func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		return auditLimitResponse(auditQuotaExhausted)
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1}, quota, io.Discard); err == nil {
		t.Fatal("quota did not pause recheck")
	}
	updated, _ := store.audit(ctx, scan.ID)
	if updated.Status != "paused" || updated.Counts["pending"] != 3 || updated.Blocked == nil {
		t.Fatalf("quota lost work: %+v", updated)
	}
	wrong := func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		return auditInvocation{StructuredOutput: `{"finding_id":99999,"outcome":"confirmed","reason":"wrong finding"}`}, nil
	}
	if err := runAudit(ctx, store, repo, updated, auditRunOptions{Jobs: 1, Limit: 1}, wrong, io.Discard); err == nil {
		t.Fatal("foreign finding result accepted")
	}
	counts, _ := store.auditRecheckCounts(ctx, scan.ID)
	if len(counts) != 0 {
		t.Fatal("failed attempt published a verification")
	}
	updated, _ = store.audit(ctx, scan.ID)
	if err := runAudit(ctx, store, repo, updated, auditRunOptions{Jobs: 2, RetryFailed: true}, auditRecheckTestRunner, io.Discard); err != nil {
		t.Fatal(err)
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 5 || attempts[0].Status != auditQuotaExhausted || attempts[1].Status != "failed" {
		t.Fatalf("retry history lost: %+v %v", attempts, err)
	}
}

func TestAuditRecheckOutputValidation(t *testing.T) {
	input := auditTaskInput{Recheck: &auditRecheckFinding{ID: 7}}
	for _, raw := range []string{
		`{"finding_id":8,"outcome":"confirmed","reason":"evidence"}`,
		`{"finding_id":7,"outcome":"resolved","reason":"evidence"}`,
		`{"finding_id":7,"outcome":"confirmed","reason":" "}`,
		`{"finding_id":7,"outcome":"confirmed","reason":"evidence","findings":[]}`,
		`{"finding_id":7,"outcome":"confirmed","reason":"evidence"} {}`,
		`{"status":"completed","summary":"ok","findings":[]}`,
	} {
		if _, err := parseAuditTaskOutput([]byte(raw), input); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestAuditRecheckCodexReceivesVerificationSchema(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	var stdout bytes.Buffer
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, CodexCommand: func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		var schema, result string
		for i, arg := range args {
			if arg == "--output-schema" {
				schema = args[i+1]
			}
			if arg == "--output-last-message" {
				result = args[i+1]
			}
		}
		data, err := os.ReadFile(schema)
		if err != nil || string(data) != auditRecheckOutputSchema {
			t.Errorf("wrong output schema: %s %v", data, err)
		}
		output, _ := json.Marshal(auditRecheckBatchOutput{Results: []auditRecheckOutput{{FindingID: findings[0].ID, Outcome: "confirmed", Reason: "fixture evidence"}}})
		return exec.CommandContext(ctx, "sh", "-c", `cat >/dev/null; printf '%s' "$1" > "$2"; printf '%s\n' '{"type":"turn.completed"}'`, "fixture", string(output), result)
	}}
	args := []string{"recheck", fmt.Sprint(findings[0].ID), "--scan", source.ID, "--model", "verifier", "--binary", testTrueBinary, "--json"}
	if err := runReposeCLI(ctx, args, env); err != nil {
		t.Fatal(err)
	}
	var scan auditScan
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil || scan.Verdicts["confirmed"] != 1 {
		t.Fatalf("schema result lost: %s %v", stdout.String(), err)
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Invocation.RawResponse == "" {
		t.Fatal("verification capture missing")
	}
}

func TestAuditRecheckV4DryRunAndMigration(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	// Reconstruct the previous schema while retaining the actual pilot records.
	if _, err := store.db.ExecContext(ctx, `DROP INDEX audit_finding_tags_by_tag;
		DROP TABLE audit_finding_tags;
		DROP TABLE config;
		DROP TABLE models;
		DROP TABLE audit_recheck_results;
		DROP INDEX audit_recheck_identity;
		ALTER TABLE audit_scans DROP COLUMN kind;
		ALTER TABLE audit_scans DROP COLUMN recheck_key;
		PRAGMA user_version=4;`); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, AuditRunner: func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		calls.Add(1)
		return auditInvocation{}, errors.New("unexpected model call")
	}}
	args := []string{"recheck", "--model", "verifier", "--binary", testTrueBinary, "--json"}
	if err := runReposeCLI(ctx, append(append([]string{}, args...), "--dry-run"), env); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		SourceScanID string  `json:"source_scan_id"`
		FindingIDs   []int64 `json:"finding_ids"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &preview); err != nil || preview.SourceScanID != source.ID || len(preview.FindingIDs) != 3 {
		t.Fatalf("wrong dry run: %s %v", stdout.String(), err)
	}
	var version, scans int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatal("dry run migrated the database")
	}
	if err := store.db.QueryRow("SELECT count(*) FROM audit_scans").Scan(&scans); err != nil || scans != 1 || calls.Load() != 0 {
		t.Fatal("dry run saved or dispatched work")
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, append(append([]string{}, args...), "--create-only"), env); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != reposeCurrentSchemaVersion || calls.Load() != 0 {
		t.Fatal("create-only did not upgrade safely")
	}
	var tagTable int
	if err := store.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='audit_finding_tags'").Scan(&tagTable); err != nil || tagTable != 1 {
		t.Fatal("finding tag migration was not applied")
	}
	var recheck auditScan
	if err := json.Unmarshal(stdout.Bytes(), &recheck); err != nil || recheck.Counts["pending"] != 3 {
		t.Fatalf("create-only failed: %s %v", stdout.String(), err)
	}
	fs := &auditFindingStore{reader: store, scanID: source.ID}
	after, err := fs.AllFindings(ctx)
	if err != nil || len(after) != len(findings) || after[0].Description != findings[0].Description {
		t.Fatal("migration changed original findings")
	}
	attempts, err := store.auditAttempts(ctx, source.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatal("migration lost original attempts")
	}
}

func TestAuditRecheckSelectionAndSnapshotGuards(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	var stdout bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, AuditRunner: func(ctx context.Context, c auditModelConfig, p string) (auditInvocation, error) {
		calls.Add(1)
		return auditRecheckTestRunner(ctx, c, p)
	}}
	base := []string{"recheck", "--scan", source.ID, "--model", "verifier", "--binary", testTrueBinary, "--create-only", "--json"}
	for _, extra := range [][]string{
		{"999999"}, {fmt.Sprint(findings[0].ID), fmt.Sprint(findings[0].ID)},
		{"--path", "../escape"}, {"--path", "not-in-scan"}, {"--timeout", "0"}, {"--jobs", "33"}, {"--model", ""},
		{"--batch-max", "0"}, {"--batch-max", "-1"},
	} {
		if err := runReposeCLI(ctx, append(append([]string{}, base...), extra...), env); err == nil {
			t.Fatalf("accepted invalid selection/options: %v", extra)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid selection dispatched work")
	}
	database, _ := reposeDatabasePath(ctx, repo)
	fs := &auditFindingStore{reader: store, databasePath: database, scanID: source.ID}
	if err := fs.DismissFinding(ctx, findings[0].ID, "exclude from recheck", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := runReposeCLI(ctx, append(append([]string{}, base...), fmt.Sprint(findings[0].ID)), env); err == nil {
		t.Fatal("dismissed finding selected explicitly")
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, append(append([]string{}, base...), fmt.Sprint(findings[1].ID)), env); err != nil {
		t.Fatal(err)
	}
	var scan auditScan
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil || scan.Counts["pending"] != 1 || scan.Spec.Recheck.Findings[0].ID != findings[1].ID {
		t.Fatalf("finding subset was not frozen: %s %v", stdout.String(), err)
	}
	writeInventoryFixtureFile(t, repo.WorkTree+"/pcbnew/main.cpp", []byte("int changed_snapshot;\n"))
	if err := runReposeCLI(ctx, []string{"scan", "resume", scan.ID}, env); err == nil || calls.Load() != 0 {
		t.Fatalf("recheck ran on changed snapshot: %v", err)
	}
}

func TestAuditRecheckBatchGroupingAndFrozenContext(t *testing.T) {
	_, store, source, findings := auditRecheckFixture(t, 7, 4, 2)
	ctx := context.Background()
	spec, err := buildAuditRecheckSpec(source, findings, source.Spec.Model, 5)
	if err != nil {
		t.Fatal(err)
	}
	reversed := slices.Clone(findings)
	slices.Reverse(reversed)
	reordered, err := buildAuditRecheckSpec(source, reversed, source.Spec.Model, 5)
	if err != nil || reordered.Recheck.Key != spec.Recheck.Key || reordered.Plan.ID != spec.Plan.ID {
		t.Fatal("finding selection order changed the frozen batches")
	}
	record, _ := store.Inventory(ctx, source.Spec.Plan.InventoryID)
	inputs, err := prepareAuditInputs(ctx, record, spec)
	if err != nil || len(inputs) != 4 {
		t.Fatalf("expected 4 batches: %d %v", len(inputs), err)
	}
	wantSizes := []int{5, 2, 4, 2}
	wantSources := []int{0, 0, 1, 2}
	seen := map[int64]bool{}
	var wantBytes int64
	for i, input := range inputs {
		original := source.Spec.Plan.Assignments[wantSources[i]]
		wantBytes += original.Bytes
		if len(input.RecheckBatch) != wantSizes[i] || spec.Recheck.Batches[i].SourceAssignmentID != original.ID {
			t.Fatalf("batch %d lost its original assignment or size: %+v", i, spec.Recheck.Batches[i])
		}
		for _, f := range input.RecheckBatch {
			if seen[f.ID] || f.TaskID != original.ID {
				t.Fatal("batch repeated a finding or crossed source assignments")
			}
			seen[f.ID] = true
		}
		_, data, _ := strings.Cut(input.Prompt, "Assignment data (line numbers are one-based, byte ranges end-exclusive):\n")
		var metadata struct {
			Sources  []json.RawMessage     `json:"sources"`
			Findings []auditRecheckFinding `json:"findings"`
		}
		if err := json.Unmarshal([]byte(data), &metadata); err != nil || len(metadata.Findings) != wantSizes[i] || len(metadata.Sources) != len(inventoryAssignmentRanges(original)) {
			t.Fatalf("batch did not share its original source context: %v", err)
		}
	}
	if len(seen) != 13 || spec.Plan.Bytes != wantBytes {
		t.Fatal("missing findings or source bytes counted per finding")
	}
	for cap, want := range map[int]int{1: 13, 3: 6, 20: 3} {
		changed, err := buildAuditRecheckSpec(source, findings, source.Spec.Model, cap)
		if err != nil || len(changed.Plan.Assignments) != want || changed.Recheck.Key == spec.Recheck.Key {
			t.Fatalf("batch-max %d did not create its own layout: %v", cap, err)
		}
	}
}

func TestAuditRecheckBatchesParallelLimitAndResume(t *testing.T) {
	repo, store, source, _ := auditRecheckFixture(t, 7, 4, 2)
	ctx := context.Background()
	var stdout bytes.Buffer
	var calls atomic.Int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, AuditRunner: func(ctx context.Context, c auditModelConfig, p string) (auditInvocation, error) {
		if calls.Add(1) <= 2 {
			entered <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return auditInvocation{}, ctx.Err()
			}
		}
		return auditRecheckTestRunner(ctx, c, p)
	}}
	args := []string{"recheck", "--model", "verifier", "--binary", testTrueBinary, "--jobs", "2", "--limit", "2", "--json"}
	done := make(chan error, 1)
	go func() { done <- runReposeCLI(ctx, args, env) }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			<-done
			t.Fatal("recheck batches did not execute concurrently")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var first auditScan
	if err := json.Unmarshal(stdout.Bytes(), &first); err != nil || first.Spec.Recheck.BatchMax != 5 || first.Counts["completed"] != 2 || first.Counts["pending"] != 2 || calls.Load() != 2 {
		t.Fatalf("limit must count batch calls: %+v %v", first.Counts, err)
	}
	count := 0
	for _, n := range first.Verdicts {
		count += n
	}
	if count != 7 {
		t.Fatalf("two batches should publish seven independent verdicts, got %d", count)
	}
	for range 2 {
		stdout.Reset()
		if err := runReposeCLI(ctx, args, env); err != nil {
			t.Fatal(err)
		}
		var resumed auditScan
		if err := json.Unmarshal(stdout.Bytes(), &resumed); err != nil || resumed.ID != first.ID || resumed.Status != "completed" || calls.Load() != 4 {
			t.Fatalf("resume did not preserve completed batches: %+v %v", resumed.Counts, err)
		}
	}
	verified, err := (&auditFindingStore{reader: store, scanID: source.ID}).AllFindings(ctx)
	if err != nil || len(verified) != 13 {
		t.Fatalf("recheck changed original findings: %v", err)
	}
	byAttempt := map[int64]int{}
	for _, f := range verified {
		if len(f.Verifications) != 1 || f.Verifications[0].FindingID != f.ID || f.Verifications[0].Outcome != []string{"confirmed", "false_positive", "uncertain"}[(f.ID-1)%3] {
			t.Fatalf("finding #%d lost its independent verdict: %+v", f.ID, f.Verifications)
		}
		byAttempt[f.Verifications[0].AttemptID]++
	}
	if len(byAttempt) != 4 {
		t.Fatalf("verdicts did not share four batch attempts: %v", byAttempt)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, append(slices.Clone(args), "--batch-max", "3", "--create-only"), env); err != nil {
		t.Fatal(err)
	}
	var changed auditScan
	if err := json.Unmarshal(stdout.Bytes(), &changed); err != nil || changed.ID == first.ID || changed.Counts["pending"] != 6 || calls.Load() != 4 {
		t.Fatal("changing batch-max reused or dispatched the original frozen pass")
	}
}

func TestAuditRecheckBatchOutputValidation(t *testing.T) {
	input := auditTaskInput{RecheckBatch: []auditRecheckFinding{{ID: 7}, {ID: 8}}}
	valid := `{"results":[{"finding_id":8,"outcome":"false_positive","reason":"caller guard"},{"finding_id":7,"outcome":"confirmed","reason":"reachable trigger"}]}`
	if output, err := parseAuditTaskOutput([]byte(valid), input); err != nil || len(output.RecheckBatch) != 2 {
		t.Fatalf("independent verdicts in response order were rejected: %v", err)
	}
	for _, raw := range []string{
		`{}`, `null`, `{"results":[]}`, `{"results":null}`,
		`{"results":[{"finding_id":7,"outcome":"confirmed","reason":"evidence"}]}`,
		strings.Replace(valid, `"finding_id":8`, `"finding_id":7`, 1),
		strings.Replace(valid, `"finding_id":8`, `"finding_id":999`, 1),
		strings.Replace(valid, `"false_positive"`, `"resolved"`, 1),
		strings.Replace(valid, `"caller guard"`, `" "`, 1),
		strings.Replace(valid, `"caller guard"`, `"caller guard","extra":true`, 1),
		valid + ` {}`,
		`{"finding_id":7,"outcome":"confirmed","reason":"legacy response"}`,
	} {
		if _, err := parseAuditTaskOutput([]byte(raw), input); err == nil {
			t.Fatalf("accepted incomplete or invalid batch: %s", raw)
		}
	}
}

func TestAuditRecheckIncompleteBatchRetry(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t, 3, 0, 0)
	ctx := context.Background()
	record, _ := store.Inventory(ctx, source.Spec.Plan.InventoryID)
	spec, err := buildAuditRecheckSpec(source, findings, source.Spec.Model, 5)
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := prepareAuditInputs(ctx, record, spec)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := store.createAudit(ctx, record, spec, inputs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	incomplete := func(ctx context.Context, c auditModelConfig, p string) (auditInvocation, error) {
		invocation, err := auditRecheckTestRunner(ctx, c, p)
		if err != nil {
			return invocation, err
		}
		var batch auditRecheckBatchOutput
		if err := json.Unmarshal([]byte(invocation.StructuredOutput), &batch); err != nil {
			return invocation, err
		}
		batch.Results = batch.Results[:2]
		raw, err := json.Marshal(batch)
		invocation.StructuredOutput = string(raw)
		return invocation, err
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 2}, incomplete, io.Discard); err == nil {
		t.Fatal("incomplete batch accepted")
	}
	failed, _ := store.audit(ctx, scan.ID)
	if failed.Counts["failed"] != 1 || len(failed.Verdicts) != 0 {
		t.Fatal("incomplete batch published partial verdicts")
	}
	if err := runAudit(ctx, store, repo, failed, auditRunOptions{Jobs: 2, RetryFailed: true}, auditRecheckTestRunner, io.Discard); err != nil {
		t.Fatal(err)
	}
	finished, _ := store.audit(ctx, scan.ID)
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || finished.Status != "completed" || len(attempts) != 2 || attempts[0].Status != "failed" || attempts[0].Invocation.RawResponse == "" || len(attempts[1].Output.RecheckBatch) != 3 {
		t.Fatalf("retry lost the failed attempt or independent results: %v", err)
	}
	verified, err := (&auditFindingStore{reader: store, scanID: source.ID}).AllFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range verified {
		if len(f.Verifications) != 1 || f.Verifications[0].AttemptID != attempts[1].ID {
			t.Fatal("failed attempt leaked a verdict")
		}
	}
}

func TestAuditRecheckV5MigrationPreservesLegacyResume(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t)
	ctx := context.Background()
	record, _ := store.Inventory(ctx, source.Spec.Plan.InventoryID)
	spec, err := buildAuditRecheckSpec(source, findings, source.Spec.Model, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate a frozen v1 pass, including its single-finding input protocol.
	spec.PromptVersion = auditRecheckPromptVersionV1
	spec.Plan.Planner = auditRecheckPromptVersionV1
	spec.Recheck.BatchMax, spec.Recheck.Batches = 0, nil
	inputs, err := prepareAuditInputs(ctx, record, spec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range inputs {
		inputs[i].Prompt = strings.Replace(inputs[i].Prompt, auditRecheckInstructions, "Verify the single supplied claim; return finding_id, outcome, and reason.", 1)
	}
	scan, err := store.createAudit(ctx, record, spec, inputs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := runAudit(ctx, store, repo, scan, auditRunOptions{Jobs: 1, Limit: 1}, auditRecheckTestRunner, io.Discard); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := store.db.QueryRow("SELECT document FROM audit_recheck_results WHERE scan_id=?", scan.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// Restore the previous primary key while retaining a completed verdict and
	// two pending tasks, then exercise the real writer's upgrade and CLI resume.
	if _, err := store.db.ExecContext(ctx, `
		DROP INDEX audit_finding_tags_by_tag;
		DROP TABLE audit_finding_tags;
		DROP TABLE config;
		DROP TABLE models;
		ALTER TABLE audit_recheck_results RENAME TO recheck_results_saved;
		DROP INDEX audit_recheck_finding;
		CREATE TABLE audit_recheck_results (
		 finding_id INTEGER NOT NULL REFERENCES audit_findings(id),
		 scan_id TEXT NOT NULL REFERENCES audit_scans(id),
		 attempt_id INTEGER PRIMARY KEY REFERENCES audit_attempts(id),
		 outcome TEXT NOT NULL CHECK(outcome IN ('confirmed','false_positive','uncertain')),
		 document TEXT NOT NULL
		);
		INSERT INTO audit_recheck_results SELECT * FROM recheck_results_saved;
		DROP TABLE recheck_results_saved;
		CREATE INDEX audit_recheck_finding ON audit_recheck_results(finding_id,attempt_id);
		PRAGMA user_version=5;`); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var calls atomic.Int32
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, CodexCommand: func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		var schema, result string
		for i, arg := range args {
			if arg == "--output-schema" {
				schema = args[i+1]
			}
			if arg == "--output-last-message" {
				result = args[i+1]
			}
		}
		data, err := os.ReadFile(schema)
		if err != nil || string(data) != auditRecheckOutputSchemaV1 {
			t.Errorf("legacy pass received the new batch protocol: %v", err)
		}
		index := int(calls.Add(1))
		if index >= len(inputs) {
			t.Error("completed legacy finding was repeated")
			return exec.CommandContext(ctx, "/bin/false")
		}
		invocation, err := auditRecheckTestRunner(ctx, spec.Model, inputs[index].Prompt)
		if err != nil {
			t.Error(err)
		}
		return exec.CommandContext(ctx, "sh", "-c", `cat >/dev/null; printf '%s' "$1" > "$2"; printf '%s\n' '{"type":"turn.completed"}'`, "fixture", invocation.StructuredOutput, result)
	}}
	if err := runReposeCLI(ctx, []string{"scan", "resume", scan.ID, "--jobs", "1", "--json"}, env); err != nil {
		t.Fatal(err)
	}
	var resumed auditScan
	if err := json.Unmarshal(stdout.Bytes(), &resumed); err != nil || resumed.Status != "completed" || resumed.ID != scan.ID || calls.Load() != 2 {
		t.Fatalf("legacy recheck could not resume: %v", err)
	}
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != reposeCurrentSchemaVersion {
		t.Fatal("legacy resume did not upgrade storage")
	}
	var after string
	if err := store.db.QueryRow("SELECT document FROM audit_recheck_results WHERE scan_id=? AND finding_id=?", scan.ID, findings[0].ID).Scan(&after); err != nil || after != before {
		t.Fatal("migration changed the completed verification")
	}
	tasks, err := store.auditTasks(ctx, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, task := range tasks {
		if task.Input.Prompt != inputs[i].Prompt || task.Input.Recheck == nil || task.Input.RecheckBatch != nil {
			t.Fatal("legacy frozen input changed")
		}
	}
	attempts, err := store.auditAttempts(ctx, scan.ID)
	if err != nil || len(attempts) != 3 {
		t.Fatalf("legacy attempt history lost: %v", err)
	}
	for _, attempt := range attempts {
		if attempt.Output.Recheck == nil || attempt.Output.RecheckBatch != nil {
			t.Fatal("legacy output changed protocol")
		}
	}
}
