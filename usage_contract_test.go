package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	usagecontract "github.com/codefly-dev/core/contracts/usage"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	agentv0 "github.com/codefly-dev/core/generated/go/codefly/services/agent/v0"
)

func parsedUsageContract(t *testing.T) *usagecontract.Contract {
	t.Helper()
	contract, err := usagecontract.Parse([]byte(usageContract))
	if err != nil {
		t.Fatalf("usage.codefly.yaml is refused by its own reader: %v", err)
	}
	return contract
}

// The agent advertises its usage contract byte for byte, so a consumer's
// tooling reads exactly the file in this repository.
func TestTheAgentAdvertisesItsUsageContractVerbatim(t *testing.T) {
	parsedUsageContract(t)
	info, err := NewService().GetAgentInformation(context.Background(), &agentv0.AgentInformationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.GetUsageContract() != usageContract || usageContract == "" {
		t.Fatalf("the advertised usage contract is not usage.codefly.yaml:\n%s", info.GetUsageContract())
	}
}

// A rule ID is permanent: an exception names it and a finding reports it.
// Adding a rule adds a line here; removing or renaming one is a decision.
func TestTheUsageRulesAreTheOnesPublished(t *testing.T) {
	want := []string{"PG-OPEN-001", "PG-POOL-001", "PG-MIGRATE-001", "PG-MAINT-001", "PG-SCOPE-001", "PG-WRITE-001"}
	contract := parsedUsageContract(t)
	if len(contract.Rules) != len(want) {
		t.Fatalf("%d rules, want %d", len(contract.Rules), len(want))
	}
	for i, id := range want {
		if contract.Rules[i].ID != id {
			t.Errorf("rule %d is %s, want %s", i+1, contract.Rules[i].ID, id)
		}
		// A rule is introduced as a warning: a consumer pinning this release
		// has had no earlier one in which to hear about it.
		if contract.Rules[i].Severity != usagecontract.SeverityWarn {
			t.Errorf("%s is introduced as %s; a new rule starts as %s", id, contract.Rules[i].Severity, usagecontract.SeverityWarn)
		}
	}
}

// A rule that forbids calling one of this library's own functions names a
// function the library exports. A rename in libs/go without the contract
// would otherwise leave a rule that can never match.
func TestEveryForbiddenLibraryCallIsExported(t *testing.T) {
	const library = "github.com/codefly-dev/service-postgres/libs/go"
	checked := 0
	for _, rule := range parsedUsageContract(t).Rules {
		clause := rule.Detects("go")
		if clause == nil {
			continue
		}
		for _, symbol := range clause.ForbidCall {
			if !strings.HasPrefix(symbol, library) {
				continue
			}
			at := strings.LastIndex(symbol, ".")
			directory := filepath.Join("libs", "go", filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(symbol[:at], library), "/")))
			if !exportsFunction(t, directory, symbol[at+1:]) {
				t.Errorf("%s forbids %s, and %s exports no such function", rule.ID, symbol, directory)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no rule forbids a call into the library; this test checks nothing")
	}
}

func exportsFunction(t *testing.T, directory, name string) bool {
	t.Helper()
	packages, err := parser.ParseDir(token.NewFileSet(), directory, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for packageName, parsed := range packages {
		if strings.HasSuffix(packageName, "_test") {
			continue
		}
		for file, source := range parsed.Files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			for _, declaration := range source.Decls {
				if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Name.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// file is one consumer source file as a language plugin's semantic index
// projects it: what it imports and the calls it makes, as written.
type file struct {
	path    string
	imports []string
	calls   []string
}

func consumerIndex(files ...file) *basev0.SemanticIndex {
	index := &basev0.SemanticIndex{State: basev0.SemanticIndexState_SEMANTIC_INDEX_STATE_COMPLETE, Languages: []string{"go"}}
	for _, source := range files {
		index.Files = append(index.Files, &basev0.SemanticFile{Path: source.path, Language: "go", Imports: source.imports})
		symbol := &basev0.SemanticSymbol{Name: "f", Location: &basev0.SemanticLocation{Path: source.path}}
		for line, call := range source.calls {
			symbol.Calls = append(symbol.Calls, &basev0.SemanticUse{Name: call, Location: &basev0.SemanticLocation{Path: source.path, StartLine: int32(line + 1), StartColumn: 1}})
		}
		index.Symbols = append(index.Symbols, symbol)
	}
	return index
}

// Every rule with a detect clause is shown a consumer that breaks it and one
// that follows it, so a clause that stopped matching, or started matching
// correct use of the library, fails here.
func TestEveryDetectableRuleCatchesAViolationAndPassesTheLibrary(t *testing.T) {
	const library = "github.com/codefly-dev/service-postgres/libs/go"
	contract := parsedUsageContract(t)
	cases := map[string]struct{ violating, complying file }{
		"PG-OPEN-001": {
			violating: file{path: "store/open.go", imports: []string{"github.com/jackc/pgx/v5/pgxpool"}, calls: []string{"pgxpool.New"}},
			complying: file{path: "store/open.go", imports: []string{library, "github.com/jackc/pgx/v5"}, calls: []string{"postgres.Open", "factory.Reader", "reader.InTransaction", "tx.Query"}},
		},
		"PG-POOL-001": {
			violating: file{path: "store/open.go", imports: []string{library}, calls: []string{"postgres.NewFactory"}},
			complying: file{path: "store/open.go", imports: []string{library}, calls: []string{"postgres.Open", "postgres.OpenMaintenance", "postgres.WithRestrictedSession"}},
		},
		"PG-MIGRATE-001": {
			violating: file{path: "cmd/server/main.go", imports: []string{library + "/migrationtest"}, calls: []string{"migrationtest.OpenControlPlane"}},
			complying: file{path: "cmd/server/main.go", imports: []string{library}, calls: []string{"postgres.Open"}},
		},
	}
	for _, rule := range contract.Rules {
		if len(rule.Detect) == 0 {
			continue
		}
		c, covered := cases[rule.ID]
		if !covered {
			t.Errorf("%s has a detect clause and no violating and complying case here", rule.ID)
			continue
		}
		only := &usagecontract.Contract{Schema: contract.Schema, Summary: contract.Summary, Rules: []usagecontract.Rule{rule}}
		if findings := only.Detect(consumerIndex(c.violating)); len(findings) == 0 {
			t.Errorf("%s does not catch its violation %+v", rule.ID, c.violating)
		}
		if findings := only.Detect(consumerIndex(c.complying)); len(findings) != 0 {
			t.Errorf("%s reports correct use of the library: %+v", rule.ID, findings)
		}
		// The same violation in a test is the library's own documented use
		// (a qualified pool handed to NewFactory), and is excepted.
		inTest := c.violating
		inTest.path = "store/open_test.go"
		if findings := only.Detect(consumerIndex(inTest)); len(findings) != 0 {
			t.Errorf("%s reports a test file: %+v", rule.ID, findings)
		}
	}
	// Whole contract, whole violating service: each detectable rule once.
	var all []file
	for id, c := range cases {
		c.violating.path = "pkg/" + strings.ToLower(id) + ".go"
		all = append(all, c.violating)
	}
	if findings := contract.Detect(consumerIndex(all...)); len(findings) != len(cases) {
		t.Errorf("a service breaking every detectable rule has %d findings, want %d: %+v", len(findings), len(cases), findings)
	}
}
