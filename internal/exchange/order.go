package exchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

var timeType = reflect.TypeOf(time.Time{})

// AssertFieldOrder decodes raw JSON and verifies that every object preserves
// the field order of the reference struct type. Nested structs, slices and
// pointers are traversed recursively. A mismatch is reported with the JSON
// pointer-style path so reviewers can locate the drift immediately.
func AssertFieldOrder(raw []byte, reference any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read json: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return fmt.Errorf("top-level json value must be an object")
	}
	return checkObject(decoder, reflect.TypeOf(reference), "$")
}

func checkObject(decoder *json.Decoder, structType reflect.Type, path string) error {
	expected := jsonFieldOrder(structType)
	seen := make([]string, 0, len(expected))

	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: read key: %w", path, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%s: non-string object key", path)
		}
		seen = append(seen, key)

		fieldType, fieldOK := fieldByName(structType, key)
		if !fieldOK {
			return fmt.Errorf("%s.%s: field not present in contract", path, key)
		}
		if err := checkValue(decoder, fieldType, path+"."+key); err != nil {
			return err
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	if len(seen) != len(expected) {
		return fmt.Errorf("%s: field count mismatch: export has %d fields, contract defines %d",
			path, len(seen), len(expected))
	}
	for index := range expected {
		if seen[index] != expected[index] {
			return fmt.Errorf("%s: field order mismatch at position %d: export=%q contract=%q",
				path, index, seen[index], expected[index])
		}
	}
	return nil
}

func checkValue(decoder *json.Decoder, valueType reflect.Type, path string) error {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	// Types with custom scalar JSON marshalling must be consumed as leaves.
	if valueType == timeType || valueType.Implements(jsonMarshalerType) ||
		reflect.PointerTo(valueType).Implements(jsonMarshalerType) {
		return skipValue(decoder)
	}

	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%s: read value: %w", path, err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		if valueType.Kind() != reflect.Struct {
			return fmt.Errorf("%s: unexpected object for non-struct type", path)
		}
		return checkObject(decoder, valueType, path)
	case '[':
		if valueType.Kind() != reflect.Slice {
			return fmt.Errorf("%s: unexpected array for non-slice type", path)
		}
		elementType := valueType.Elem()
		index := 0
		for decoder.More() {
			if err := checkValue(decoder, elementType, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		return expectDelimiter(decoder, ']')
	default:
		return fmt.Errorf("%s: unexpected delimiter %q", path, delimiter)
	}
}

var jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// skipValue consumes one complete JSON value without interpreting it.
func skipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
		return expectDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
		return expectDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
}

func expectDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	got, ok := token.(json.Delim)
	if !ok || got != want {
		return fmt.Errorf("expected delimiter %q, got %v", want, token)
	}
	return nil
}

func jsonFieldOrder(structType reflect.Type) []string {
	if structType.Kind() != reflect.Struct {
		return nil
	}
	fields := make([]string, 0, structType.NumField())
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if !field.IsExported() {
			continue
		}
		name := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			name = splitTag(tag)
			if name == "-" {
				continue
			}
		}
		fields = append(fields, name)
	}
	return fields
}

func fieldByName(structType reflect.Type, jsonName string) (reflect.Type, bool) {
	if structType.Kind() != reflect.Struct {
		return nil, false
	}
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if !field.IsExported() {
			continue
		}
		name := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			name = splitTag(tag)
			if name == "-" {
				continue
			}
		}
		if name == jsonName {
			return field.Type, true
		}
	}
	return nil, false
}

func splitTag(tag string) string {
	for index := 0; index < len(tag); index++ {
		if tag[index] == ',' {
			return tag[:index]
		}
	}
	return tag
}
