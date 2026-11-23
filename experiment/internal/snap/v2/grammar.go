package v2

import "fmt"

func (p *parser) skipWS() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '-'
}

func (p *parser) readName() string {
	start := p.pos
	for p.pos < len(p.src) && isNameChar(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) parseNode() (*Node, error) {
	p.skipWS()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("unexpected end of node")
	}
	switch p.src[p.pos] {
	case '&':
		p.pos++
		name := p.readName()
		if name == "" {
			return nil, fmt.Errorf("empty anchor name")
		}
		body, err := p.parseNode()
		if err != nil {
			return nil, err
		}
		p.anchors[name] = body
		return body, nil
	case '*':
		p.pos++
		name := p.readName()
		if name == "" {
			return nil, fmt.Errorf("empty alias name")
		}
		return &Node{Kind: Alias, Scalar: name}, nil
	case '[':
		return p.parseSeq()
	case '{':
		return p.parseMap()
	default:
		return p.readScalar()
	}
}

func (p *parser) parseSeq() (*Node, error) {
	p.pos++ // consume '['
	n := &Node{Kind: Seq}
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		return n, nil
	}
	for {
		child, err := p.parseNode()
		if err != nil {
			return nil, err
		}
		n.Children = append(n.Children, child)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, fmt.Errorf("unterminated sequence")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return n, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.pos)
		}
	}
}

func (p *parser) parseMap() (*Node, error) {
	p.pos++ // consume '{'
	n := &Node{Kind: Map}
	p.skipWS()
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		return n, nil
	}
	for {
		p.skipWS()
		key := p.readName()
		if key == "" {
			return nil, fmt.Errorf("empty map key at offset %d", p.pos)
		}
		p.skipWS()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, fmt.Errorf("expected ':' after map key %q", key)
		}
		p.pos++
		child, err := p.parseNode()
		if err != nil {
			return nil, err
		}
		n.Keys = append(n.Keys, key)
		n.Children = append(n.Children, child)
		p.skipWS()
		if p.pos >= len(p.src) {
			return nil, fmt.Errorf("unterminated map")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return n, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.pos)
		}
	}
}

func (p *parser) readScalar() (*Node, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ',' || c == ']' || c == '}' {
			break
		}
		p.pos++
	}
	s := p.src[start:p.pos]
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	s = s[:end]
	if s == "" {
		return nil, fmt.Errorf("empty scalar at offset %d", start)
	}
	return &Node{Kind: Scalar, Scalar: s}, nil
}
