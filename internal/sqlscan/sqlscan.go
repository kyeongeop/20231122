package sqlscan

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type Token struct {
	Text  string
	Upper string
	Start int
	End   int
}

type Span struct {
	Text  string
	Start int
	End   int
}

func SplitStatements(sql string) []Span {
	var spans []Span
	start := 0
	for i := 0; i < len(sql); {
		switch {
		case sql[i] == '\'' || sql[i] == '"' || sql[i] == '`':
			i = skipQuoted(sql, i, sql[i])
		case sql[i] == '[':
			i = skipBracket(sql, i)
		case sql[i] == '-' && i+1 < len(sql) && sql[i+1] == '-':
			i = skipLineComment(sql, i)
		case sql[i] == '/' && i+1 < len(sql) && sql[i+1] == '*':
			i = skipBlockComment(sql, i)
		case sql[i] == ';':
			if span, ok := trimSpan(sql, start, i); ok {
				spans = append(spans, span)
			}
			start = i + 1
			i++
		default:
			_, size := utf8.DecodeRuneInString(sql[i:])
			if size == 0 {
				size = 1
			}
			i += size
		}
	}
	if span, ok := trimSpan(sql, start, len(sql)); ok {
		spans = append(spans, span)
	}
	return spans
}

func Tokens(sql string, limit int) []Token {
	var tokens []Token
	for i := 0; i < len(sql); {
		switch {
		case isSpace(sql[i]):
			i++
		case sql[i] == '-' && i+1 < len(sql) && sql[i+1] == '-':
			i = skipLineComment(sql, i)
		case sql[i] == '/' && i+1 < len(sql) && sql[i+1] == '*':
			i = skipBlockComment(sql, i)
		case sql[i] == '\'' || sql[i] == '"' || sql[i] == '`':
			i = skipQuoted(sql, i, sql[i])
		case sql[i] == '[':
			i = skipBracket(sql, i)
		case isWordStart(sql[i]):
			start := i
			i++
			for i < len(sql) && isWordPart(sql[i]) {
				i++
			}
			text := sql[start:i]
			tokens = append(tokens, Token{
				Text:  text,
				Upper: strings.ToUpper(text),
				Start: start,
				End:   i,
			})
			if limit > 0 && len(tokens) >= limit {
				return tokens
			}
		default:
			i++
		}
	}
	return tokens
}

func FirstToken(sql string) (Token, bool) {
	tokens := Tokens(sql, 1)
	if len(tokens) == 0 {
		return Token{}, false
	}
	return tokens[0], true
}

func LineColumn(sql string, offset int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(sql) {
		offset = len(sql)
	}
	line, column := 1, 1
	for i := 0; i < offset; {
		if sql[i] == '\n' {
			line++
			column = 1
			i++
			continue
		}
		_, size := utf8.DecodeRuneInString(sql[i:])
		if size == 0 {
			size = 1
		}
		column++
		i += size
	}
	return line, column
}

func skipQuoted(s string, i int, quote byte) int {
	i++
	for i < len(s) {
		if s[i] == quote {
			if i+1 < len(s) && s[i+1] == quote {
				i += 2
				continue
			}
			return i + 1
		}
		i++
	}
	return i
}

func skipBracket(s string, i int) int {
	i++
	for i < len(s) {
		if s[i] == ']' {
			return i + 1
		}
		i++
	}
	return i
}

func skipLineComment(s string, i int) int {
	i += 2
	for i < len(s) && s[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(s string, i int) int {
	i += 2
	for i+1 < len(s) {
		if s[i] == '*' && s[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return len(s)
}

func trimSpan(s string, start, end int) (Span, bool) {
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	if start >= end {
		return Span{}, false
	}
	return Span{Text: s[start:end], Start: start, End: end}, true
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func isWordStart(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= utf8.RuneSelf || unicode.IsLetter(rune(b))
}

func isWordPart(b byte) bool {
	return isWordStart(b) || b >= '0' && b <= '9' || b == '$'
}
