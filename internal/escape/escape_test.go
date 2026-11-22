package escape

import (
	"strings"
	"testing"
)

func TestRenderEscapesVariables(t *testing.T) {
	res, err := Render([]byte(`<p>{{msg}}</p>`), map[string]string{
		"msg": `<script>"x"&'y'</script>`,
	}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := `<p>&lt;script&gt;&#34;x&#34;&amp;&#39;y&#39;&lt;/script&gt;</p>`
	if string(res.Output) != want {
		t.Fatalf("got %q want %q", res.Output, want)
	}
	if res.Degraded {
		t.Fatal("unexpected degradation")
	}
}

func TestRenderDeterministic(t *testing.T) {
	tmpl := []byte(`{{a}}-{{b}}-{{c}}`)
	vars := map[string]string{"a": "1&", "b": "<2>", "c": `"3"`}
	r1, _ := Render(tmpl, vars, Limits{})
	r2, _ := Render(tmpl, vars, Limits{})
	if string(r1.Output) != string(r2.Output) {
		t.Fatal("non-deterministic output")
	}
}

func TestValueTruncationDegrades(t *testing.T) {
	res, err := Render([]byte(`{{v}}`), map[string]string{"v": "abcdefghij"},
		Limits{MaxValueBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != "abcd" {
		t.Fatalf("got %q", res.Output)
	}
	if !res.Degraded || len(res.Events) != 1 || res.Events[0].Kind != EventValueTruncated {
		t.Fatalf("events=%+v", res.Events)
	}
	if res.Events[0].Offset != 0 {
		t.Fatalf("offset=%d", res.Events[0].Offset)
	}
}

func TestOutputBudgetDegrades(t *testing.T) {
	res, err := Render([]byte(`AAAA{{v}}BBBB`), map[string]string{"v": "xy"},
		Limits{MaxOutputBytes: 5})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != "AAAAx" {
		t.Fatalf("got %q", res.Output)
	}
	if !res.Degraded {
		t.Fatal("expected degradation")
	}
	found := false
	for _, e := range res.Events {
		if e.Kind == EventOutputTruncated && e.Offset == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("events=%+v", res.Events)
	}
}

func TestHardLimits(t *testing.T) {
	if _, err := Render([]byte(`123456`), nil, Limits{MaxTemplateBytes: 3}); err != ErrTemplateTooLarge {
		t.Fatalf("err=%v", err)
	}
	if _, err := Render([]byte(`{{a}}{{b}}`), map[string]string{"a": "1", "b": "2"},
		Limits{MaxVars: 1}); err != ErrTooManyVars {
		t.Fatalf("err=%v", err)
	}
}

func TestUnknownVarAndUnterminated(t *testing.T) {
	res, err := Render([]byte(`{{nope}} tail {{open`), map[string]string{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Output) != " tail {{open" {
		t.Fatalf("got %q", res.Output)
	}
	var kinds []string
	for _, e := range res.Events {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != EventUnknownVar+","+EventUnterminated {
		t.Fatalf("kinds=%v", kinds)
	}
}
