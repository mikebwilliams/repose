package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func auditTagFixture(t *testing.T) (*GitRepository, *inventoryStore, auditScan, *auditFindingStore, []Finding) {
	t.Helper()
	repository, store, scan, inputs := auditFixture(t)
	ctx := context.Background()
	if err := runAudit(ctx, store, repository, scan, auditRunOptions{Jobs: 2}, auditTestRunner(inputs), io.Discard); err != nil {
		t.Fatal(err)
	}
	database, err := reposeDatabasePath(ctx, repository)
	if err != nil {
		t.Fatal(err)
	}
	backend := &auditFindingStore{reader: store, databasePath: database, scanID: scan.ID}
	findings, err := backend.AllFindings(ctx)
	if err != nil || len(findings) != 3 {
		t.Fatalf("findings: %d %v", len(findings), err)
	}
	return repository, store, scan, backend, findings
}

func TestAuditFindingTagsBulkAtomicAndIdempotent(t *testing.T) {
	_, store, _, backend, findings := auditTagFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ids := []int64{findings[0].ID, findings[1].ID, findings[2].ID}
	changes, err := backend.TagFindings(ctx, ids, []string{"Triage:High-Value", "crash"}, now)
	if err != nil || changes != 6 {
		t.Fatalf("bulk tag: %d %v", changes, err)
	}
	changes, err = backend.TagFindings(ctx, ids, []string{"crash", "triage:high-value"}, now.Add(time.Minute))
	if err != nil || changes != 0 {
		t.Fatalf("idempotent bulk tag: %d %v", changes, err)
	}
	loaded, err := backend.AllFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range loaded {
		if !slices.Equal(finding.Tags, []string{"crash", "triage:high-value"}) {
			t.Fatalf("tags were not normalized and sorted: %+v", finding)
		}
		var taggedEvents int
		events, err := backend.FindingEvents(ctx, finding.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Action == "tagged" {
				taggedEvents++
			}
		}
		if taggedEvents != 2 {
			t.Fatalf("idempotent edit wrote duplicate history: %+v", events)
		}
	}
	if _, err := backend.TagFindings(ctx, []int64{ids[0], 9999999}, []string{"atomic"}, now); err == nil {
		t.Fatal("missing finding did not reject the complete edit")
	}
	var atomicTags int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_finding_tags WHERE tag='atomic'").Scan(&atomicTags); err != nil || atomicTags != 0 {
		t.Fatalf("failed bulk edit partially committed: %d %v", atomicTags, err)
	}
	if _, err := backend.TagFindings(ctx, []int64{ids[0], ids[0]}, []string{"duplicate"}, now); err == nil {
		t.Fatal("duplicate finding ID accepted")
	}
	changes, err = backend.UntagFindings(ctx, ids[:2], []string{"crash"}, now.Add(2*time.Minute))
	if err != nil || changes != 2 {
		t.Fatalf("bulk untag: %d %v", changes, err)
	}
	loaded, err = backend.AllFindings(ctx)
	if err != nil || len(loaded[0].Tags) != 1 || len(loaded[1].Tags) != 1 || len(loaded[2].Tags) != 2 {
		t.Fatalf("bulk untag result: %+v %v", loaded, err)
	}
	model := newFindingsModel(ctx, findingExternalCommands{snapshot: true}, backend, loaded, auditFindingDisplay(loaded), true, func() time.Time { return now.Add(3 * time.Minute) })
	selectedID := model.selectedID()
	model.input = "from-tui"
	model.tagSelected(true)
	loaded, err = backend.AllFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundTUITag := false
	for _, finding := range loaded {
		if finding.ID == selectedID {
			foundTUITag = slices.Contains(finding.Tags, "from-tui")
		}
	}
	if !foundTUITag {
		t.Fatalf("TUI tag edit did not persist: %+v %v", loaded, err)
	}
}

func TestAuditFindingTagCLIListsAndFilters(t *testing.T) {
	repository, _, scan, _, findings := auditTagFixture(t)
	ctx := context.Background()
	var stdout bytes.Buffer
	environment := cliEnvironment{Cwd: repository.WorkTree, Stdout: &stdout, Stderr: io.Discard, Now: func() time.Time { return time.Now().UTC() }}
	ids := []string{fmt.Sprint(findings[0].ID), fmt.Sprint(findings[1].ID)}
	args := []string{"finding", "tag", ids[0], ids[1], "--tag", "Triage:High-Value", "--tag", "crash", "--repo", repository.WorkTree}
	if err := runReposeCLI(ctx, args, environment); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Added 4 tag assignments across 2 findings") {
		t.Fatalf("unexpected tag output: %s", stdout.String())
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"findings", "--repo", repository.WorkTree, "--scan", scan.ID, "--tag", "crash", "--tag", "triage:high-value", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var selected []Finding
	if err := json.Unmarshal(stdout.Bytes(), &selected); err != nil || len(selected) != 2 || !slices.Equal(selected[0].Tags, []string{"crash", "triage:high-value"}) {
		t.Fatalf("findings tag filter: %+v %v", selected, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"tags", "--repo", repository.WorkTree, "--scan", "latest", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var counts []findingTagCount
	if err := json.Unmarshal(stdout.Bytes(), &counts); err != nil || len(counts) != 2 || counts[0].Tag != "crash" || counts[0].Findings != 2 {
		t.Fatalf("tag counts: %+v %v", counts, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"export", "--repo", repository.WorkTree, "--format", "json", "--tag", "crash"}, environment); err != nil {
		t.Fatal(err)
	}
	var report auditExportReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || len(report.Findings) != 2 || !slices.Equal(report.Findings[0].Tags, []string{"crash", "triage:high-value"}) {
		t.Fatalf("tag-filtered export: %+v %v", report, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"export", "--repo", repository.WorkTree, "--format", "sarif", "--tag", "crash"}, environment); err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(stdout.Bytes(), &sarif); err != nil || len(sarif.Runs[0].Results) != 2 || !slices.Equal(sarif.Runs[0].Results[0].Properties.Tags, []string{"crash", "triage:high-value"}) {
		t.Fatalf("SARIF tags: %+v %v", sarif, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"export", "--repo", repository.WorkTree, "--format", "html", "--tag", "crash"}, environment); err != nil {
		t.Fatal(err)
	}
	html := decodeAuditHTMLExport(t, stdout.String())
	if len(html.Findings) != 2 || !slices.Equal(html.Findings[0].Tags, []string{"crash", "triage:high-value"}) || !strings.Contains(stdout.String(), "function matchesTags") || !strings.Contains(stdout.String(), "tags (AND)") {
		t.Fatalf("HTML tags: %+v", html.Findings)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"recheck", "--repo", repository.WorkTree, "--scan", scan.ID, "--model", "verifier", "--binary", testTrueBinary, "--tag", "crash", "--dry-run", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var preview struct {
		FindingIDs []int64 `json:"finding_ids"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &preview); err != nil || !slices.Equal(preview.FindingIDs, []int64{findings[0].ID, findings[1].ID}) {
		t.Fatalf("tag-filtered recheck: %+v %v", preview, err)
	}
	if err := runReposeCLI(ctx, []string{"finding", "tag", ids[0], "9999999", "--tag", "must-not-stick", "--repo", repository.WorkTree}, environment); err == nil {
		t.Fatal("CLI accepted a partially invalid ID list")
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"findings", "--repo", repository.WorkTree, "--tag", "must-not-stick", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &selected); err != nil || len(selected) != 0 {
		t.Fatalf("invalid CLI edit partially committed: %+v %v", selected, err)
	}
}

func TestFindingTagValidationAndTUIFiltering(t *testing.T) {
	for _, valid := range []string{"crash", "needs-context", "class:ownership", "area/pcbnew", "p1.urgent"} {
		if _, err := normalizeFindingTag(valid); err != nil {
			t.Errorf("valid tag %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", ":class", "two words", "#123", strings.Repeat("a", 65)} {
		if _, err := normalizeFindingTag(invalid); err == nil {
			t.Errorf("invalid tag %q accepted", invalid)
		}
	}
	findings := []Finding{{ID: 1, Severity: "warning", Title: "one", Tags: []string{"crash", "parser"}}, {ID: 2, Severity: "warning", Title: "two", Tags: []string{"parser"}}}
	model := newFindingsModel(context.Background(), findingExternalCommands{snapshot: true}, nil, findings, nil, true, time.Now)
	model.tagFilters = []string{"crash", "parser"}
	model.applyFilters(0)
	if len(model.visible) != 1 || model.visible[0].ID != 1 || !strings.Contains(findingSearchText(findings[0]), "crash") {
		t.Fatalf("TUI tag search/filter failed: %+v", model.visible)
	}
	if detail := strings.Join(model.detailLines(100), "\n"); !strings.Contains(detail, "Tags: crash, parser") {
		t.Fatalf("TUI detail omitted tags: %s", detail)
	}
}
