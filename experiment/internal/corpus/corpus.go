// Package corpus builds the experiment object set and sniffs content
// types independently of file extension.
package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

type Object struct {
	ID      string
	Name    string // file name, extension may be unknown/misleading
	Content []byte
}

func (o Object) Ext() string { return filepath.Ext(o.Name) }

func (o Object) SHA256() string {
	sum := sha256.Sum256(o.Content)
	return hex.EncodeToString(sum[:])
}

// Sniff classifies content without trusting the file extension.
func Sniff(data []byte) string {
	if len(strings.TrimSpace(string(data))) == 0 {
		return "empty"
	}
	lines := 0
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if !strings.Contains(ln, ":") {
			return "unknown"
		}
		lines++
	}
	if lines > 0 {
		return "yaml-subset"
	}
	return "unknown"
}

// bomb builds a classic "billion laughs" alias-expansion payload:
// 9 anchors, each aliasing the previous 10 times -> ~10^10 expanded nodes.
func bomb() []byte {
	var b strings.Builder
	fmt.Fprintln(&b, `l1: &a1 ["lol","lol","lol","lol","lol","lol","lol","lol","lol","lol"]`)
	for i := 2; i <= 9; i++ {
		fmt.Fprintf(&b, "l%d: &a%d [", i, i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		fmt.Fprintln(&b, "]")
	}
	b.WriteString("boom: [*a9,*a9,*a9,*a9,*a9,*a9,*a9,*a9,*a9,*a9]\n")
	return []byte(b.String())
}

// Default returns the ordered experiment corpus. bomb uses an unknown
// extension (.qzx) on purpose; fault-empty is an injected fault object
// used to prove the runner continues after exceptions.
func Default() []Object {
	return []Object{
		{ID: "obj-benign", Name: "benign.yaml",
			Content: []byte("name: demo\nitems: [1, 2, 3]\nmeta: {env: lab, run: one}\n")},
		{ID: "obj-bomb", Name: "bomb.qzx", Content: bomb()},
		{ID: "obj-moderate", Name: "moderate.yaml",
			Content: []byte("base: &b [1, 2, 3]\npair: &p [*b, *b]\nquad: [*p, *p]\n")},
		{ID: "obj-broken", Name: "broken.yaml",
			Content: []byte("key: [unclosed\n")},
		{ID: "obj-selfref", Name: "selfref.yaml",
			Content: []byte("a: &x [*x]\n")},
		{ID: "obj-fault", Name: "fault-empty.dat", Content: []byte{}},
	}
}
