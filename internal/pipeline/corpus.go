// Package pipeline implements the pausable filename-processing flow:
// an extreme-parameter corpus organized around "missing fragment"
// filenames, checkpointed into SQLite, resumable, with degradation
// handling and boundary sampling.
package pipeline

import (
	"fmt"
	"strings"
)

// Item is one corpus entry: a filename plus the parameters that built it.
type Item struct {
	ID       int
	Name     string
	Fragment string // missing-fragment template id
	Trick    string // unicode trick applied
	Pos      string // padding position: prefix|middle|suffix
}

// fragments are filenames built around a missing fragment: a missing
// stem segment, a missing path segment, a missing ASCII dot, a missing
// UTF-8 continuation byte, a missing visual order (RLO), etc.
var fragments = []struct {
	id   string
	name string
}{
	{"missing-stem", "report..exe"},
	{"missing-path-seg", "dir//payload.exe"},
	{"missing-dot", "photo․exe"},                // U+2024 one-dot-leader
	{"missing-cont-byte", "pay\xc3load.exe"},    // truncated UTF-8
	{"missing-visual-order", "invoice‮exe.jpg"}, // U+202E RLO
	{"missing-ascii-delim", "setup．ｅｘｅ"},        // fullwidth delimiters
	{"missing-trailing-trim", "update.exe."},
	{"missing-ext-dot", "archive/tar..gz"},
}

// tricks are Unicode transformations layered on a fragment.
var tricks = []struct {
	id string
	fn func(string) string
}{
	{"none", func(s string) string { return s }},
	{"zwsp-inject", func(s string) string { return strings.Replace(s, ".", "​.", 1) }},
	{"cyrillic-ext", func(s string) string {
		return strings.Replace(s, "exe", "еxe", 1) // Cyrillic е
	}},
	{"trailing-space", func(s string) string { return s + " " }},
}

// padTargets are extreme total byte lengths, bracketing the NAME_MAX
// boundary (255/256) and one page boundary (4095/4096).
var padTargets = []int{0, 254, 255, 256, 257, 4095, 4096}

// positions are padding placements relative to the fragment.
var positions = []string{"prefix", "middle", "suffix"}

func padTo(name string, target int, pos string) string {
	if target <= 0 || len(name) >= target {
		return name
	}
	pad := strings.Repeat("A", target-len(name))
	switch pos {
	case "prefix":
		return pad + name
	case "middle":
		i := len(name) / 2
		return name[:i] + pad + name[i:]
	default:
		return name + pad
	}
}

// Generate builds the deterministic corpus: every fragment x trick x
// pad target x padding position. Item IDs are stable across runs so a
// resumed run reproduces exactly the same stream.
func Generate() []Item {
	var items []Item
	id := 0
	for _, frag := range fragments {
		for _, trick := range tricks {
			base := trick.fn(frag.name)
			for _, target := range padTargets {
				for _, pos := range positions {
					if target == 0 && pos != "prefix" {
						continue // unpadded variant only once
					}
					items = append(items, Item{
						ID:       id,
						Name:     padTo(base, target, pos),
						Fragment: frag.id,
						Trick:    trick.id,
						Pos:      pos,
					})
					id++
				}
			}
		}
	}
	return items
}

func (it Item) String() string {
	return fmt.Sprintf("#%d[%s/%s/%s len=%d]", it.ID, it.Fragment, it.Trick, it.Pos, len(it.Name))
}
