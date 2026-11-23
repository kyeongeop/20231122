// Package v1 is the vulnerable snapshot of the mini YAML-subset parser.
// It expands anchors/aliases with no resource limits, so alias bombs
// cause exponential memory/cpu exhaustion. Frozen for the experiment.
package v1

import (
	"fmt"
	"strings"
)

type Kind int

const (
	Scalar Kind = iota
	Seq
	Map
	Alias
)

type Node struct {
	Kind     Kind
	Scalar   string
	Keys     []string
	Children []*Node
}

type Metrics struct {
	ExpandedNodes int `json:"expanded_nodes"`
	AliasRefs     int `json:"alias_refs"`
	MaxDepth      int `json:"max_depth"`
}

type parser struct {
	src     string
	pos     int
	anchors map[string]*Node
}

func Parse(data []byte) (*Node, *Metrics, error) {
	p := &parser{anchors: map[string]*Node{}}
	root := &Node{Kind: Map}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			return nil, nil, fmt.Errorf("invalid line %q: missing ':'", line)
		}
		p.src = strings.TrimSpace(rest)
		p.pos = 0
		n, err := p.parseNode()
		if err != nil {
			return nil, nil, fmt.Errorf("line %q: %w", line, err)
		}
		if strings.TrimSpace(p.src[p.pos:]) != "" {
			return nil, nil, fmt.Errorf("line %q: trailing data", line)
		}
		root.Keys = append(root.Keys, strings.TrimSpace(key))
		root.Children = append(root.Children, n)
	}
	m := &Metrics{}
	exp, err := p.expand(root, 0, m)
	if err != nil {
		return nil, m, err
	}
	return exp, m, nil
}

func (p *parser) expand(n *Node, depth int, m *Metrics) (*Node, error) {
	m.ExpandedNodes++
	if depth > m.MaxDepth {
		m.MaxDepth = depth
	}
	switch n.Kind {
	case Scalar:
		return n, nil
	case Alias:
		m.AliasRefs++
		target, ok := p.anchors[n.Scalar]
		if !ok {
			return nil, fmt.Errorf("undefined alias *%s", n.Scalar)
		}
		return p.expand(target, depth+1, m)
	case Seq, Map:
		out := &Node{Kind: n.Kind, Keys: n.Keys}
		for _, c := range n.Children {
			ec, err := p.expand(c, depth+1, m)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, ec)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown node kind %d", n.Kind)
}
