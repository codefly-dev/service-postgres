package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// An agent reads AGENTS.md on every request, so an oversized or malformed set of
// context files is worse than none: it spends context and measurably reduces
// adherence (obin-ai/handbook#68). Two parts of that standard a machine can
// hold are the root file's length budget and each skill's frontmatter contract,
// so they are checked here rather than remembered.
//
// These are tests rather than a workflow step because `go test ./...` already
// runs in CI, so the guard needs no change to ci.yml — which is itself under
// test in workflow_test.go.

const (
	agentContextFile   = "AGENTS.md"
	claudePointerFile  = "CLAUDE.md"
	maxRootLines       = 200
	maxSkillBodyLines  = 500
	maxNameChars       = 64
	maxDescriptionSize = 1024
)

var skillNameShape = regexp.MustCompile(`^[a-z0-9-]+$`)

func readAgentContextLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func TestAgentContextRootStaysWithinItsBudget(t *testing.T) {
	lines := len(readAgentContextLines(t, agentContextFile))

	require.LessOrEqualf(t, lines, maxRootLines,
		"%s is %d lines, over the %d-line cap. Move procedure into .claude/skills/, "+
			"or context into a nested AGENTS.md beside what it describes. Do not append.",
		agentContextFile, lines, maxRootLines)
}

// One canonical source: CLAUDE.md points at AGENTS.md instead of drifting from
// it. Two files saying nearly the same thing means an agent reads whichever one
// rotted.
func TestClaudeFileIsOnlyAPointer(t *testing.T) {
	raw, err := os.ReadFile(claudePointerFile)
	require.NoError(t, err)

	require.Equal(t, "@"+agentContextFile, strings.TrimSpace(string(raw)),
		"%s must stay a pointer line '@%s' so there is one canonical source.",
		claudePointerFile, agentContextFile)
}

// splitSkillFrontmatter returns the fields a SKILL.md declares in the YAML block
// it opens with, and the body that follows. Only the two fields the skill
// contract requires are read, so the guard adds no YAML dependency.
func splitSkillFrontmatter(t *testing.T, path string) (map[string]string, []string) {
	t.Helper()
	lines := readAgentContextLines(t, path)

	require.Equalf(t, "---", lines[0],
		"%s does not open with a '---' frontmatter block, so nothing about the "+
			"skill is declared and it is never loaded.", path)

	end := -1
	for i, line := range lines[1:] {
		if line == "---" {
			end = i + 1
			break
		}
	}
	require.Positivef(t, end, "%s opens a frontmatter block that is never closed.", path)

	fields := make(map[string]string)
	for _, line := range lines[1:end] {
		key, value, found := strings.Cut(line, ":")
		require.Truef(t, found, "%s frontmatter line %q is not 'key: value'.", path, line)
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return fields, lines[end+1:]
}

// A skill's frontmatter is all an agent sees before deciding to load it: a name
// that does not match its directory, or a missing description, makes the skill
// unreachable without failing anything else — it rots invisibly.
func TestSkillsDeclareAUsableNameAndDescription(t *testing.T) {
	skills, err := filepath.Glob(filepath.Join(".claude", "skills", "*", "SKILL.md"))
	require.NoError(t, err)
	require.NotEmpty(t, skills, "no skills found — the glob or the layout moved")

	for _, skill := range skills {
		directory := filepath.Base(filepath.Dir(skill))

		t.Run(directory, func(t *testing.T) {
			fields, body := splitSkillFrontmatter(t, skill)
			name, description := fields["name"], fields["description"]

			require.Equalf(t, directory, name,
				"%s declares name %q but sits in %q; an agent resolves a skill by its "+
					"directory, so the two must agree.", skill, name, directory)
			require.Regexpf(t, skillNameShape, name,
				"%s name %q must be lowercase letters, digits and hyphens.", skill, name)
			require.LessOrEqualf(t, len(name), maxNameChars,
				"%s name is %d characters, over %d.", skill, len(name), maxNameChars)

			require.NotEmptyf(t, description,
				"%s has no description — an agent cannot tell when to load it.", skill)
			require.LessOrEqualf(t, len(description), maxDescriptionSize,
				"%s description is %d characters, over %d.",
				skill, len(description), maxDescriptionSize)

			require.LessOrEqualf(t, len(body), maxSkillBodyLines,
				"%s body is %d lines, over the %d-line cap. Split the detail into "+
					"reference files the skill reads when it needs them.",
				skill, len(body), maxSkillBodyLines)
		})
	}
}
