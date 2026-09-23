package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditExportFormatsWithVerificationHistory(t *testing.T) {
	repo, store, source, findings := auditRecheckFixture(t, 3, 1, 0)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	var stdout bytes.Buffer
	env := cliEnvironment{Cwd: t.TempDir(), Stdout: &stdout, Stderr: io.Discard, AuditRunner: auditRecheckTestRunner, Now: func() time.Time { return now }}
	var recheck auditScan
	for _, model := range []string{"verifier", "second-verifier"} {
		stdout.Reset()
		if err := runReposeCLI(ctx, []string{"recheck", "--repo", repo.WorkTree, "--scan", source.ID, "--model", model, "--binary", testTrueBinary, "--json"}, env); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(stdout.Bytes(), &recheck); err != nil || recheck.Status != "completed" {
			t.Fatalf("recheck setup failed: %v", err)
		}
	}
	database, _ := reposeDatabasePath(ctx, repo)
	fs := &auditFindingStore{reader: store, databasePath: database, scanID: source.ID}
	if err := fs.DismissFinding(ctx, findings[1].ID, "Human disposition remains authoritative.", now); err != nil {
		t.Fatal(err)
	}
	unsafe := `</script><script>window.exportInjection=true</script>`
	if err := fs.AddFindingNote(ctx, findings[0].ID, unsafe, now); err != nil {
		t.Fatal(err)
	}
	// Export reads the observed commit, even after local source changes.
	writeInventoryFixtureFile(t, filepath.Join(repo.WorkTree, *findings[0].File), []byte("replacement contents from the live checkout\n"))
	export := func(format string, extra ...string) string {
		t.Helper()
		stdout.Reset()
		args := append([]string{"export", "--repo", repo.WorkTree, "--format", format}, extra...)
		if err := runReposeCLI(ctx, args, env); err != nil {
			t.Fatal(err)
		}
		return stdout.String()
	}
	jsonOutput := export("json", "--scan", "latest")
	var report auditExportReport
	if err := json.Unmarshal([]byte(jsonOutput), &report); err != nil || len(report.Findings) != 3 || report.ScanID != source.ID || report.GeneratedAt != now.Format(time.RFC3339) {
		t.Fatalf("JSON export selection or metadata: %+v %v", report, err)
	}
	if strings.Contains(jsonOutput, "introduced_sha") {
		t.Fatal("snapshot export attributes findings to introducing commits")
	}
	first := report.Findings[0]
	if first.ID != findings[0].ID || first.Review == nil || first.Review.Model != source.Spec.Model.Model || first.ObservedSHA != source.Spec.Plan.SnapshotSHA || first.TaskID != findings[0].TaskID || first.AttemptID != findings[0].AttemptID || len(first.Events) != 4 || len(first.Verifications) != 2 || first.Verifications[1].Model != "second-verifier" {
		t.Fatalf("JSON export lost provenance or history: %+v", first)
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"--all"}, 4},
		{[]string{"--scan", recheck.ID}, 3},
		{[]string{"--verification", "false_positive"}, 0},
		{[]string{"--all", "--verification", "false_positive"}, 1},
		{[]string{"--verification", "confirmed"}, 2},
		{[]string{"--verification", "unchecked"}, 0},
		{[]string{"--path", *findings[0].File}, 2},
		{[]string{"--path", "not-in-scan"}, 0},
	} {
		if err := json.Unmarshal([]byte(export("json", tc.args...)), &report); err != nil || report.Findings == nil || len(report.Findings) != tc.want {
			t.Fatalf("filter %v: got %d, want %d: %v", tc.args, len(report.Findings), tc.want, err)
		}
	}
	var sarif sarifLog
	if err := json.Unmarshal([]byte(export("sarif", "--all")), &sarif); err != nil || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 4 {
		t.Fatalf("SARIF export: %+v %v", sarif, err)
	}
	if sarif.Runs[0].Tool.Driver.Name != "Repose" || sarif.Runs[0].Tool.Driver.Rules[0].ID != "REPOSE" {
		t.Fatal("SARIF retained AIR's tool identity")
	}
	for i, result := range sarif.Runs[0].Results {
		if result.RuleID != "REPOSE" || result.Properties.IntroducedBy != "" || result.Properties.ObservedSHA != findings[i].ObservedSHA || result.Properties.ScanID != source.ID || result.Properties.Review == nil || len(result.Properties.Verifications) != 2 || len(result.Properties.Events) < 3 || result.Fingerprints["repose/finding-id"] == "" {
			t.Fatalf("SARIF lost audit/verification details: %+v", result)
		}
	}
	if sarif.Runs[0].Results[1].Properties.Disposition != "dismissed" {
		t.Fatal("SARIF --all lost the manual disposition")
	}
	output := export("html", "--scan", source.ID)
	for _, expected := range []string{"Repose Findings Report", "Source at observed snapshot", `id="search"`, `id="verification"`, `id="tag-filter"`, "function matchesSearch", "function matchesTags", "function revealHashFinding", "function renderVerifications", "</html>"} {
		if !strings.Contains(output, expected) {
			t.Errorf("HTML missing %q", expected)
		}
	}
	if strings.Contains(output, unsafe) || strings.Contains(output, "<script src=") || strings.Contains(output, "<link rel=") {
		t.Fatal("HTML export is unsafe or depends on external resources")
	}
	html := decodeAuditHTMLExport(t, output)
	if !html.Snapshot || html.Title != "Repose Findings Report" || len(html.Findings) != 4 || html.InitialStatus != "open" {
		t.Fatalf("HTML must retain all dispositions: %+v", html)
	}
	for _, f := range html.Findings {
		if f.IntroducedSHA != "" || f.Author != "" || f.CommitDate != "" || f.ObservedSHA != source.Spec.Plan.SnapshotSHA || f.ObservedAt == nil || f.Review == nil || len(f.Verifications) != 2 || len(f.Diff.Lines) == 0 || f.Diff.Error != "" || !strings.HasPrefix(f.Diff.HunkHeader, "Snapshot ") {
			t.Fatalf("HTML lost snapshot source or verification: %+v", f)
		}
		if strings.Contains(strings.Join(f.Diff.Lines, "\n"), "replacement contents from the live checkout") {
			t.Fatal("HTML preview used live checkout source")
		}
	}
	if html.Findings[1].DismissReason == "" || html.Findings[0].Events[3].Note != unsafe {
		t.Fatal("HTML dropped manual history")
	}
	filtered := decodeAuditHTMLExport(t, export("html", "--all", "--verification", "false_positive"))
	if len(filtered.Findings) != 1 || filtered.InitialStatus != "all" || filtered.Verification != "false_positive" {
		t.Fatal("HTML ignored scope or initial filters")
	}
	if output := export("html", "-o", "report.html"); output != "" {
		t.Fatal("file export also wrote to stdout")
	}
	data, err := os.ReadFile(filepath.Join(env.Cwd, "report.html"))
	if err != nil || !strings.Contains(string(data), "Repose Findings Report") {
		t.Fatalf("relative output path did not use caller's directory: %v", err)
	}
	if !json.Valid([]byte(export("json", "-o", "-"))) {
		t.Fatal("-o - did not write JSON to stdout")
	}
}

func decodeAuditHTMLExport(t *testing.T, output string) htmlExportReport {
	t.Helper()
	_, data, ok := strings.Cut(output, `<script id="air-data" type="application/json">`)
	if !ok {
		t.Fatal("missing embedded export data")
	}
	data, _, ok = strings.Cut(data, "</script>")
	var report htmlExportReport
	if err := json.Unmarshal([]byte(data), &report); !ok || err != nil {
		t.Fatalf("invalid embedded export data: %v", err)
	}
	return report
}

func TestAuditExportReadOnlyV4AndValidation(t *testing.T) {
	repo, store, _, _ := auditRecheckFixture(t)
	ctx := context.Background()
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
	env := cliEnvironment{Cwd: repo.WorkTree, Stdout: &stdout, Stderr: io.Discard, AuditRunner: func(context.Context, auditModelConfig, string) (auditInvocation, error) {
		t.Fatal("export invoked a model")
		return auditInvocation{}, nil
	}}
	for _, format := range []string{"json", "sarif", "html"} {
		stdout.Reset()
		if err := runReposeCLI(ctx, []string{"export", "--format", format, "--scan", "latest"}, env); err != nil {
			t.Fatal(err)
		}
	}
	var version, scans, attempts int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatal("export migrated the database")
	}
	if err := store.db.QueryRow("SELECT count(*) FROM audit_scans").Scan(&scans); err != nil || scans != 1 {
		t.Fatal("export changed scans")
	}
	if err := store.db.QueryRow("SELECT count(*) FROM audit_attempts").Scan(&attempts); err != nil || attempts != 3 {
		t.Fatal("export dispatched attempts")
	}
	output := filepath.Join(t.TempDir(), "existing-report.json")
	if err := os.WriteFile(output, []byte("keep this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--format", "xml"}, {"--format", "json", "unexpected"}, {"--format", "json", "--verification", "bad"}, {"--format", "json", "--path", "../escape"}, {"--format", "html", "--scan", "bad"}} {
		command := append([]string{"export", "-o", output}, args...)
		if err := runReposeCLI(ctx, command, env); err == nil {
			t.Fatalf("accepted bad export args %v", args)
		}
		data, err := os.ReadFile(output)
		if err != nil || string(data) != "keep this file" {
			t.Fatal("invalid export clobbered its destination")
		}
	}
}
