package exchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
)

// CanonicalJSON serializes a value with stable field order and compact
// separators. Structs keep their declaration order (the review contract),
// while maps are sorted by key and whitespace is removed so the output is
// byte-identical across machines and runs.
func CanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := encodeCanonical(&buffer, reflect.ValueOf(value)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

func encodeCanonical(buffer *bytes.Buffer, value reflect.Value) error {
	if !value.IsValid() {
		buffer.WriteString("null")
		return nil
	}

	// Types with custom marshalling (e.g. time.Time, json.RawMessage) emit
	// themselves as compact scalar/structured JSON.
	if value.CanInterface() {
		if marshaler, ok := value.Interface().(json.Marshaler); ok {
			return writeMarshaled(buffer, marshaler)
		}
		if value.CanAddr() {
			if marshaler, ok := value.Addr().Interface().(json.Marshaler); ok {
				return writeMarshaled(buffer, marshaler)
			}
		}
	}

	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			buffer.WriteString("null")
			return nil
		}
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Bool:
		if value.Bool() {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buffer.WriteString(strconv.FormatInt(value.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buffer.WriteString(strconv.FormatUint(value.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		encoded, err := json.Marshal(value.Float())
		if err != nil {
			return err
		}
		buffer.Write(encoded)
	case reflect.String:
		encoded, err := json.Marshal(value.String())
		if err != nil {
			return err
		}
		buffer.Write(encoded)
	case reflect.Slice, reflect.Array:
		if value.Type() == rawMessageType {
			buffer.Write(value.Bytes())
			return nil
		}
		buffer.WriteByte('[')
		for index := 0; index < value.Len(); index++ {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := encodeCanonical(buffer, value.Index(index)); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case reflect.Map:
		return encodeMap(buffer, value)
	case reflect.Struct:
		return encodeStruct(buffer, value)
	default:
		encoded, err := json.Marshal(value.Interface())
		if err != nil {
			return err
		}
		buffer.Write(encoded)
	}
	return nil
}

func writeMarshaled(buffer *bytes.Buffer, marshaler json.Marshaler) error {
	encoded, err := marshaler.MarshalJSON()
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, encoded); err != nil {
		return err
	}
	buffer.Write(compact.Bytes())
	return nil
}

func encodeMap(buffer *bytes.Buffer, value reflect.Value) error {
	keys := make([]string, 0, value.Len())
	keyValues := make(map[string]reflect.Value, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		key := iterator.Key().String()
		keys = append(keys, key)
		keyValues[key] = iterator.Value()
	}
	sort.Strings(keys)
	buffer.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			buffer.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return err
		}
		buffer.Write(encodedKey)
		buffer.WriteByte(':')
		if err := encodeCanonical(buffer, keyValues[key]); err != nil {
			return err
		}
	}
	buffer.WriteByte('}')
	return nil
}

func encodeStruct(buffer *bytes.Buffer, value reflect.Value) error {
	buffer.WriteByte('{')
	first := true
	structType := value.Type()
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if !field.IsExported() {
			continue
		}
		name, omitEmpty := jsonFieldName(field)
		if name == "-" {
			continue
		}
		fieldValue := value.Field(index)
		if omitEmpty && fieldValue.IsZero() {
			continue
		}
		if !first {
			buffer.WriteByte(',')
		}
		first = false
		encodedKey, err := json.Marshal(name)
		if err != nil {
			return err
		}
		buffer.Write(encodedKey)
		buffer.WriteByte(':')
		if err := encodeCanonical(buffer, fieldValue); err != nil {
			return err
		}
	}
	buffer.WriteByte('}')
	return nil
}

func jsonFieldName(field reflect.StructField) (name string, omitEmpty bool) {
	name = field.Name
	tag := field.Tag.Get("json")
	if tag == "" {
		return name, false
	}
	parts := splitTagParts(tag)
	if parts[0] != "" {
		name = parts[0]
	}
	for _, option := range parts[1:] {
		if option == "omitempty" {
			omitEmpty = true
		}
	}
	return name, omitEmpty
}

func splitTagParts(tag string) []string {
	var parts []string
	start := 0
	for index := 0; index <= len(tag); index++ {
		if index == len(tag) || tag[index] == ',' {
			parts = append(parts, tag[start:index])
			start = index + 1
		}
	}
	return parts
}

// SHA256Hex returns the lowercase hex SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
