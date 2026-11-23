package callback

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
)

// ErrEmptyBody 回调体为空。
var ErrEmptyBody = errors.New("empty callback body")

// Parse 兼容旧格式（form 编码）与新格式（JSON），输出规范化视图。
// 解析失败本身也是可复核事件，由调用方记录到 StageParse。
func Parse(contentType string, body []byte) (*Callback, error) {
	cb := &Callback{
		Raw:         append([]byte(nil), body...),
		ContentType: contentType,
		Fields:      map[string]string{},
		ParsedAt:    time.Now().UTC(),
	}
	if len(body) == 0 {
		return nil, ErrEmptyBody
	}

	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch {
	case ct == "application/json" || looksLikeJSON(body):
		cb.Format = FormatV2
		if err := parseJSON(cb, body); err != nil {
			return cb, err
		}
	default:
		cb.Format = FormatLegacy
		if err := parseForm(cb, body); err != nil {
			return cb, err
		}
	}
	normalizeLegacyAliases(cb)
	return cb, nil
}

func looksLikeJSON(body []byte) bool {
	for _, b := range body {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		return b == '{' || b == '['
	}
	return false
}

func parseForm(cb *Callback, body []byte) error {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}
	for key, vals := range values {
		if len(vals) == 0 {
			continue
		}
		// 重复参数是注入特征：保留全部值，主值取第一个。
		cb.Fields[key] = vals[0]
		if len(vals) > 1 {
			cb.Fields[key+".repeated"] = strings.Join(vals, "|")
		}
	}
	mapFields(cb)
	return nil
}

func parseJSON(cb *Callback, body []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	for key, val := range raw {
		switch v := val.(type) {
		case string:
			cb.Fields[key] = v
		case nil:
			cb.Fields[key] = ""
		default:
			// 非字符串标量/嵌套对象原样序列化，避免静默丢证据。
			encoded, _ := json.Marshal(v)
			cb.Fields[key] = string(encoded)
		}
	}
	mapFields(cb)
	return nil
}

func mapFields(cb *Callback) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := cb.Fields[k]; ok {
				return v
			}
		}
		return ""
	}
	cb.Code = get("code", "authorization_code")
	cb.State = get("state")
	cb.Error = get("error")
	cb.ErrorDesc = get("error_description", "errorDescription")
	cb.RedirectURI = get("redirect_uri", "redirectUri")
	cb.Issuer = get("iss", "issuer")
	cb.ResponseMode = get("response_mode", "responseMode")
	cb.TokenHash = get("token_hash", "tokenHash")
}

// normalizeLegacyAliases 处理旧版本字段别名，保证下游判断一致。
func normalizeLegacyAliases(cb *Callback) {
	if cb.ResponseMode == "" {
		if v, ok := cb.Fields["resp_mode"]; ok {
			cb.ResponseMode = v
		}
	}
	if cb.RedirectURI == "" {
		if v, ok := cb.Fields["redirect_url"]; ok {
			cb.RedirectURI = v
		}
	}
}
