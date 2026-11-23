// Package v2 is the hardened snapshot of the mini YAML-subset parser.
// Same grammar as v1, but alias expansion is bounded by explicit
// resource limits. Frozen for the experiment.
package v2

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

type Limits struct {
	MaxInputBytes    int `json:"max_input_bytes"`
	MaxAliases       int `json:"max_aliases"`
	MaxExpandedNodes int `json:"max_expanded_nodes"`
	MaxDepth         int `json:"max_depth"`
}

func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:    1 << 20,
		MaxAliases:       64,
		MaxExpandedNodes: 10000,
		MaxDepth:         64,
	}
}

type LimitError struct {
	What  string `json:"what"`
	Limit int    `json:"limit"`
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("resource limit exceeded: %s (limit %d)", e.What, e.Limit)
}

type parser struct {
	src     string
	pos     int
	anchors map[string]*Node
	lim     Limits
	m       *Metrics
}

func Parse(data []byte, lim Limits) (*Node, *Metrics, error) {
	if len(data) > lim.MaxInputBytes {
		return nil, nil, &LimitError{What: "input_bytes", Limit: lim.MaxInputBytes}
	}
	p := &parser{anchors: map[string]*Node{}, lim: lim, m: &Metrics{}}
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
	exp, err := p.expand(root, 0)
	if err != nil {
		return nil, p.m, err
	}
	return exp, p.m, nil
}

func (p *parser) expand(n *Node, depth int) (*Node, error) {
	p.m.ExpandedNodes++
	if p.m.ExpandedNodes > p.lim.MaxExpandedNodes {
		return nil, &LimitError{What: "expanded_nodes", Limit: p.lim.MaxExpandedNodes}
	}
	if depth > p.lim.MaxDepth {
		return nil, &LimitError{What: "expansion_depth", Limit: p.lim.MaxDepth}
	}
	if depth > p.m.MaxDepth {
		p.m.MaxDepth = depth
	}
	switch n.Kind {
	case Scalar:
		return n, nil
	case Alias:
		p.m.AliasRefs++
		if p.m.AliasRefs > p.lim.MaxAliases {
			return nil, &LimitError{What: "alias_refs", Limit: p.lim.MaxAliases}
		}
		target, ok := p.anchors[n.Scalar]
		if !ok {
			return nil, fmt.Errorf("undefined alias *%s", n.Scalar)
		}
		return p.expand(target, depth+1)
	case Seq, Map:
		out := &Node{Kind: n.Kind, Keys: n.Keys}
		for _, c := range n.Children {
			ec, err := p.expand(c, depth+1)
			if err != nil {
				return nil, err
			}
			out.Children = append(out.Children, ec)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown node kind %d", n.Kind)
}
