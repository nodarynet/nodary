package canonical

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// parse walks a JSON document into the intermediate representation.
//
// It uses the token stream rather than decoding into map[string]any because a
// map cannot represent a duplicate key: encoding/json keeps the last occurrence
// and reports nothing. RFC 8259 leaves that outcome to the parser, so an object
// with a repeated name has no single canonical form and must be refused rather
// than silently resolved.
func parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	v, err := parseValue(dec, "")
	if err != nil {
		return nil, err
	}
	// A canonical document is exactly one value. Trailing content means the
	// input was not what the caller thought it was.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected content after top-level value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder, path string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseToken(dec, tok, path)
}

func parseToken(dec *json.Decoder, tok json.Token, path string) (any, error) {
	delim, ok := tok.(json.Delim)
	if !ok {
		// nil, bool, string and json.Number all pass straight through.
		return tok, nil
	}

	switch delim {
	case '{':
		obj := make(map[string]any)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, fmt.Errorf("object key is not a string")
			}
			if _, dup := obj[key]; dup {
				return nil, at(path+"."+key, errDuplicateKey)
			}
			val, err := parseValue(dec, path+"."+key)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return nil, err
		}
		return obj, nil

	case '[':
		arr := []any{}
		for i := 0; dec.More(); i++ {
			val, err := parseValue(dec, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected delimiter %v", delim)
}

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	jsonNumberType    = reflect.TypeOf(json.Number(""))
)

// fromGo converts a Go value into the intermediate representation.
//
// Everything outside the documented domain is refused rather than guessed at.
// The two cases worth naming: a type carrying its own MarshalJSON or MarshalText
// has an encoding this package would not honour — time.Time is the one that
// matters, since encoding it field-by-field would produce bytes no other
// implementation agrees with — and a []byte would silently become base64.
func fromGo(v any, path string) (any, error) {
	if v == nil {
		return nil, nil
	}
	return fromValue(reflect.ValueOf(v), path)
}

func fromValue(rv reflect.Value, path string) (any, error) {
	if !rv.IsValid() {
		return nil, nil
	}

	// json.Number is data, not a marshaler, so it is checked before the
	// marshaler rejection below.
	if rv.Type() == jsonNumberType {
		return json.Number(rv.String()), nil
	}
	if implementsMarshaler(rv.Type()) {
		return nil, at(path, fmt.Errorf("%w: %s defines its own JSON encoding",
			ErrUnsupportedType, rv.Type()))
	}

	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return fromValue(rv.Elem(), path)

	case reflect.Bool:
		return rv.Bool(), nil

	case reflect.String:
		return rv.String(), nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int(), nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint(), nil

	case reflect.Float64:
		return rv.Float(), nil

	case reflect.Slice, reflect.Array:
		// A []byte would become base64 under encoding/json. Producing that
		// silently from a byte slice the caller thought was an array is the
		// kind of surprise this domain exists to prevent.
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return nil, at(path, fmt.Errorf(
				"%w: %s would encode as base64; convert it explicitly",
				ErrUnsupportedType, rv.Type()))
		}
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil, nil
		}
		out := make([]any, rv.Len())
		for i := range rv.Len() {
			e, err := fromValue(rv.Index(i), fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = e
		}
		return out, nil

	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return nil, at(path, fmt.Errorf("%w: map key is %s, want string",
				ErrUnsupportedType, rv.Type().Key()))
		}
		if rv.IsNil() {
			return nil, nil
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			e, err := fromValue(iter.Value(), path+"."+k)
			if err != nil {
				return nil, err
			}
			out[k] = e
		}
		return out, nil

	case reflect.Struct:
		return fromStruct(rv, path)
	}

	return nil, at(path, fmt.Errorf("%w: %s", ErrUnsupportedType, rv.Type()))
}

func fromStruct(rv reflect.Value, path string) (any, error) {
	rt := rv.Type()
	out := make(map[string]any, rt.NumField())

	for i := range rt.NumField() {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" && opts == "" {
			continue
		}
		// omitempty makes a field's presence depend on its value, so absent,
		// null and empty become three different hashes for what the caller
		// thinks is one record. Its semantics also differ between
		// encoding/json v1 and v2.
		if opts != "" {
			return nil, at(path+"."+f.Name, fmt.Errorf(
				"%w: struct tag option %q is not supported; every field is always present",
				ErrUnsupportedType, opts))
		}
		if name == "" {
			name = f.Name
		}
		if _, dup := out[name]; dup {
			return nil, at(path+"."+name, errDuplicateKey)
		}
		e, err := fromValue(rv.Field(i), path+"."+name)
		if err != nil {
			return nil, err
		}
		out[name] = e
	}
	return out, nil
}

func implementsMarshaler(t reflect.Type) bool {
	if t.Implements(jsonMarshalerType) || t.Implements(textMarshalerType) {
		return true
	}
	if t.Kind() != reflect.Pointer {
		pt := reflect.PointerTo(t)
		return pt.Implements(jsonMarshalerType) || pt.Implements(textMarshalerType)
	}
	return false
}
