package smuggle_test

import (
	"testing"

	"github.com/kyeongeop/20231122/internal/httpwire"
	"github.com/kyeongeop/20231122/internal/scenario"
	"github.com/kyeongeop/20231122/internal/smuggle"
)

func analyzeScenario(t *testing.T, name string) *smuggle.Analysis {
	t.Helper()
	for _, sc := range scenario.All() {
		if sc.Name == name {
			opts := scenario.OptionsFor(sc)
			return smuggle.Analyze(sc.Name, sc.Build(), opts, sc.Frontend, sc.Backend)
		}
	}
	t.Fatalf("scenario %s not found", name)
	return nil
}

func TestCLTESmugglesAdminRequest(t *testing.T) {
	a := analyzeScenario(t, "CASE-CLTE")
	if !a.Desync {
		t.Fatal("CL.TE should desync")
	}
	if len(a.Smuggled) != 1 || a.Smuggled[0].Path != "/admin" {
		t.Fatalf("smuggled = %+v, want one GET /admin", a.Smuggled)
	}
	// The smuggled /admin request must be denied: it carries no admin token.
	var denied bool
	for _, d := range a.Decisions {
		if d.Path == "/admin" && !d.Allowed {
			denied = true
		}
	}
	if !denied {
		t.Fatal("smuggled /admin request was not denied")
	}
}

func TestTECLAbsorbsPrefix(t *testing.T) {
	a := analyzeScenario(t, "CASE-TECL")
	if !a.Desync {
		t.Fatal("TE.CL should desync")
	}
	if a.Reuse.FrontendServed != 2 || a.Reuse.BackendServed != 1 {
		t.Fatalf("served fe=%d be=%d, want 2/1", a.Reuse.FrontendServed, a.Reuse.BackendServed)
	}
}

func TestEmptyInputHandled(t *testing.T) {
	a := analyzeScenario(t, "CASE-EMPTY")
	if a.InputSize != 0 {
		t.Fatalf("input size = %d, want 0", a.InputSize)
	}
	if a.Frontend[0].Status != "empty" {
		t.Fatalf("frontend status = %q, want empty", a.Frontend[0].Status)
	}
}

func TestOversizeRejectedAtIngress(t *testing.T) {
	a := analyzeScenario(t, "CASE-OVERSIZE")
	if a.Frontend[0].Status != "rejected" {
		t.Fatalf("frontend status = %q, want rejected", a.Frontend[0].Status)
	}
	if a.Reuse.FrontendServed != 0 {
		t.Fatalf("oversize input served %d requests", a.Reuse.FrontendServed)
	}
}

func TestBoundaryPair(t *testing.T) {
	before := analyzeScenario(t, "BOUNDARY-BEFORE")
	after := analyzeScenario(t, "BOUNDARY-AFTER")
	if before.Frontend[0].Status != "ok" {
		t.Fatalf("boundary-before status = %q, want ok", before.Frontend[0].Status)
	}
	if after.Frontend[0].Status != "rejected" {
		t.Fatalf("boundary-after status = %q, want rejected", after.Frontend[0].Status)
	}
}

func TestAdminTokenAuthorizes(t *testing.T) {
	req := &httpwire.Request{Path: "/admin"}
	req.Headers = append(req.Headers, httpwire.Header{Name: "X-Admin-Token", Value: "s3cr3t-adm1n"})
	a := smuggle.Analyze("admin-auth",
		[]byte("GET /admin HTTP/1.1\r\nHost: api.local\r\nX-Admin-Token: s3cr3t-adm1n\r\n\r\n"),
		smuggle.DefaultOptions(), httpwire.Frontend, httpwire.Backend)
	for _, d := range a.Decisions {
		if d.Path == "/admin" && !d.Allowed {
			t.Fatalf("valid admin token denied: %s", d.Reason)
		}
	}
}
