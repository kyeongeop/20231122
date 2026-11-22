package fuzzrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"apiskew.local/apiskew/internal/domain"
)

func TestLibFuzzerAndGoAgree(t *testing.T) {
	binary := os.Getenv("APISKEW_FUZZER")
	if binary == "" {
		binary = filepath.Join("..", "..", "build", "apiskew_fuzz")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skip("libFuzzer binary not built; set APISKEW_FUZZER")
	}
	scenario := domain.DefaultScenario()
	cases := []domain.Attack{
		{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 4500},
		{ActorRole: domain.RoleEditor, Action: domain.ActionRead, TenantMatch: true, SkewBMS: 0},
		{ActorRole: domain.RoleOwner, Action: domain.ActionUpdate, TenantMatch: true, SkewBMS: 9000},
		{ActorRole: domain.RoleViewer, Action: domain.ActionRead, TenantMatch: false, SkewBMS: 9000},
		{ActorRole: domain.RoleOutsider, Action: domain.ActionDelete, TenantMatch: true, SkewBMS: 12000},
		{ActorRole: domain.RoleEditor, Action: domain.ActionDelete, TenantMatch: true, SkewAMS: -9000, SkewBMS: 4500},
	}
	workDir := t.TempDir()
	for index, attack := range cases {
		input := domain.MustEncodeAttack(attack)
		evaluation, err := domain.Evaluate(scenario, input, "test")
		if err != nil {
			t.Fatal(err)
		}
		result, err := VerifyOne(context.Background(), binary, workDir, scenario, input)
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		if result.Detected != evaluation.Comparison.PermissionDifference {
			t.Fatalf("case %d fuzzer detected=%t, go difference=%t", index, result.Detected, evaluation.Comparison.PermissionDifference)
		}
	}
}
