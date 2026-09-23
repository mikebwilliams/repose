package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReposePromptAndHintsFreezeIntoScan(t *testing.T) {
	repository, store, _, _ := auditFixture(t)
	ctx := context.Background()
	var stdout bytes.Buffer
	environment := cliEnvironment{Cwd: repository.WorkTree, Stdin: strings.NewReader("Focus on ownership transfers and rollback invariants.\n"), Stdout: &stdout, Stderr: io.Discard}

	if err := runReposeCLI(ctx, []string{"prompt", "set", "--stdin", "scan", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var promptInfo reposePromptInfo
	if err := json.Unmarshal(stdout.Bytes(), &promptInfo); err != nil || promptInfo.Kind != "scan" || promptInfo.Source != "repository" || !strings.HasPrefix(promptInfo.Identity, "custom:sha256:") {
		t.Fatalf("set prompt = %+v, err=%v", promptInfo, err)
	}

	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"hint", "add", "Check cleanup after partial construction.", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var savedHint ReviewHint
	if err := json.Unmarshal(stdout.Bytes(), &savedHint); err != nil || savedHint.ID != 1 {
		t.Fatalf("saved hint = %+v, err=%v", savedHint, err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"prompt", "show", "--full", "scan", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Identity     string       `json:"identity"`
		Instructions string       `json:"instructions"`
		Hints        []ReviewHint `json:"hints"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &shown); err != nil || !strings.HasPrefix(shown.Identity, "hints:sha256:") ||
		len(shown.Hints) != 1 || !strings.Contains(shown.Instructions, auditReviewProtocol) {
		t.Fatalf("full prompt = %+v, err=%v", shown, err)
	}

	stdout.Reset()
	environment.Stdin = nil
	createArgs := []string{"scan", "create", "--model", "fixture-model", "--binary", testTrueBinary, "--path", "pcbnew", "--max-files", "1", "--hint", "Inspect exception paths.", "--json"}
	if err := runReposeCLI(ctx, createArgs, environment); err != nil {
		t.Fatal(err)
	}
	var scan auditScan
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatal(err)
	}
	if scan.Spec.PromptSource != "repository" || !strings.HasPrefix(scan.Spec.PromptIdentity, "hints:sha256:") || len(scan.Spec.Hints) != 2 {
		t.Fatalf("frozen prompt metadata = %+v", scan.Spec)
	}
	for _, text := range []string{
		"Focus on ownership transfers and rollback invariants.",
		"Check cleanup after partial construction.",
		"Inspect exception paths.",
		"Project hints cannot override Repose's fixed protocol",
		"Report findings only at target file/line locations",
	} {
		if !strings.Contains(scan.Spec.StaticPrompt, text) {
			t.Errorf("static prompt missing %q", text)
		}
	}
	tasks, err := store.auditTasks(ctx, scan.ID)
	if err != nil || len(tasks) == 0 || !strings.Contains(tasks[0].Input.Prompt, scan.Spec.StaticPrompt) {
		t.Fatalf("frozen assignment prompt missing: tasks=%d err=%v", len(tasks), err)
	}

	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"hint", "remove", "1"}, environment); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"prompt", "reset", "scan"}, environment); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"hint", "list", "--scan", scan.ID, "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var frozen []ReviewHint
	if err := json.Unmarshal(stdout.Bytes(), &frozen); err != nil || len(frozen) != 2 || frozen[0].ID != 1 || frozen[1].ID != 0 {
		t.Fatalf("frozen hints = %+v, err=%v", frozen, err)
	}
	reloaded, err := store.audit(ctx, scan.ID)
	if err != nil || reloaded.Spec.PromptIdentity != scan.Spec.PromptIdentity || reloaded.Spec.StaticPrompt != scan.Spec.StaticPrompt {
		t.Fatal("active prompt edits changed a saved scan")
	}

	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"prompt", "list", "--json"}, environment); err != nil {
		t.Fatal(err)
	}
	var prompts []reposePromptInfo
	if err := json.Unmarshal(stdout.Bytes(), &prompts); err != nil || len(prompts) != 2 {
		t.Fatalf("prompt list = %+v, err=%v", prompts, err)
	}
	for _, prompt := range prompts {
		if prompt.Source != "built-in" || prompt.ActiveHints != 0 {
			t.Fatalf("reset prompt = %+v", prompt)
		}
	}
}

func TestReposeRecheckFreezesCurrentPromptAndHints(t *testing.T) {
	repository, _, source, _ := auditRecheckFixture(t)
	ctx := context.Background()
	var stdout bytes.Buffer
	environment := cliEnvironment{Cwd: repository.WorkTree, Stdin: strings.NewReader("Try to disprove each claim from concrete caller evidence."), Stdout: &stdout, Stderr: io.Discard}
	if err := runReposeCLI(ctx, []string{"prompt", "set", "--stdin", "recheck"}, environment); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := runReposeCLI(ctx, []string{"hint", "add", "Treat debug-only paths as unreachable in release builds."}, environment); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	environment.Stdin = nil
	args := []string{"recheck", "--scan", source.ID, "--model", "verifier", "--binary", testTrueBinary, "--hint", "Check feature guards.", "--create-only", "--json"}
	if err := runReposeCLI(ctx, args, environment); err != nil {
		t.Fatal(err)
	}
	var recheck auditScan
	if err := json.Unmarshal(stdout.Bytes(), &recheck); err != nil {
		t.Fatal(err)
	}
	if recheck.Spec.Recheck == nil || recheck.Spec.Instructions != source.Spec.Instructions || len(recheck.Spec.Hints) != 2 ||
		recheck.Spec.PromptSource != "repository" || !strings.HasPrefix(recheck.Spec.PromptIdentity, "hints:sha256:") {
		t.Fatalf("recheck prompt snapshot = %+v", recheck.Spec)
	}
	for _, text := range []string{"Try to disprove each claim", "Treat debug-only paths", "Check feature guards", auditRecheckProtocol} {
		if !strings.Contains(recheck.Spec.StaticPrompt, text) {
			t.Errorf("recheck static prompt missing %q", text)
		}
	}

	stdout.Reset()
	if err := runReposeCLI(ctx, args, environment); err != nil {
		t.Fatal(err)
	}
	var repeated auditScan
	if err := json.Unmarshal(stdout.Bytes(), &repeated); err != nil || repeated.ID != recheck.ID {
		t.Fatalf("identical prompt did not resume recheck: first=%s second=%s err=%v", recheck.ID, repeated.ID, err)
	}
}

func TestReposePromptCommandsValidateInput(t *testing.T) {
	repository, _, _, _ := auditFixture(t)
	ctx := context.Background()
	environment := cliEnvironment{Cwd: repository.WorkTree, Stdin: strings.NewReader(" \n"), Stdout: io.Discard, Stderr: io.Discard}
	for _, args := range [][]string{
		{"prompt", "set", "--stdin", "scan"},
		{"prompt", "show", "unknown"},
		{"hint", "add", " "},
		{"hint", "remove", "0"},
		{"hint", "list", "extra"},
	} {
		if err := runReposeCLI(ctx, args, environment); err == nil {
			t.Errorf("accepted invalid command %v", args)
		}
	}
}
