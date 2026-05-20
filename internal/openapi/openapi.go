package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/getkin/kin-openapi/openapi3"
)

// Load parses an OpenAPI 3 spec and synthesizes one request per operation
// using example/default values. The output uses ngehe's har.Request type so
// it flows through the same scope filter + replay pipeline as a HAR import.
func Load(path string, scope config.Scope, baseOverride string) ([]har.Request, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load openapi: %w", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		// Validation failures are common in real specs — log and continue.
		fmt.Println("openapi: spec failed strict validation, continuing:", err)
	}

	base := baseOverride
	if base == "" && len(doc.Servers) > 0 {
		base = doc.Servers[0].URL
	}
	if base == "" {
		return nil, fmt.Errorf("no server URL in spec; pass --base")
	}
	base = strings.TrimRight(base, "/")

	var out []har.Request
	for path, pathItem := range doc.Paths.Map() {
		for method, op := range pathItem.Operations() {
			req, err := synthesize(base, path, method, op)
			if err != nil {
				continue
			}
			out = append(out, req)
		}
	}
	return out, nil
}

func synthesize(base, path, method string, op *openapi3.Operation) (har.Request, error) {
	resolved := path
	query := url.Values{}
	headers := map[string]string{}

	for _, paramRef := range op.Parameters {
		if paramRef.Value == nil {
			continue
		}
		p := paramRef.Value
		val := exampleScalar(p.Schema, p.Example)
		switch p.In {
		case "path":
			resolved = strings.ReplaceAll(resolved, "{"+p.Name+"}", val)
		case "query":
			query.Set(p.Name, val)
		case "header":
			headers[p.Name] = val
		}
	}

	fullURL := base + resolved
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}
	u, err := url.Parse(fullURL)
	if err != nil {
		return har.Request{}, err
	}

	r := har.Request{
		Method:  strings.ToUpper(method),
		URL:     fullURL,
		Host:    u.Host,
		Path:    u.Path,
		Headers: headers,
		Query:   urlValuesToMap(query),
	}

	if op.RequestBody != nil && op.RequestBody.Value != nil {
		for mime, mediaType := range op.RequestBody.Value.Content {
			body := exampleBody(mediaType)
			if body == nil {
				continue
			}
			r.Body = body
			r.ContentType = mime
			break
		}
	}
	return r, nil
}

func exampleScalar(schemaRef *openapi3.SchemaRef, example interface{}) string {
	if example != nil {
		return fmt.Sprint(example)
	}
	if schemaRef == nil || schemaRef.Value == nil {
		return "1"
	}
	s := schemaRef.Value
	if s.Example != nil {
		return fmt.Sprint(s.Example)
	}
	if s.Default != nil {
		return fmt.Sprint(s.Default)
	}
	if len(s.Enum) > 0 {
		return fmt.Sprint(s.Enum[0])
	}
	if s.Type == nil {
		return "1"
	}
	switch {
	case s.Type.Is("integer"), s.Type.Is("number"):
		return "1"
	case s.Type.Is("boolean"):
		return "false"
	case s.Type.Is("string"):
		switch s.Format {
		case "uuid":
			return "00000000-0000-0000-0000-000000000001"
		case "email":
			return "test@example.com"
		case "date":
			return "2024-01-01"
		case "date-time":
			return "2024-01-01T00:00:00Z"
		}
		return "x"
	}
	return "x"
}

func exampleBody(mt *openapi3.MediaType) []byte {
	if mt.Example != nil {
		b, _ := json.Marshal(mt.Example)
		return b
	}
	if len(mt.Examples) > 0 {
		for _, ex := range mt.Examples {
			if ex.Value != nil && ex.Value.Value != nil {
				b, _ := json.Marshal(ex.Value.Value)
				return b
			}
		}
	}
	if mt.Schema == nil || mt.Schema.Value == nil {
		return nil
	}
	v := generateFromSchema(mt.Schema.Value, 0)
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

func generateFromSchema(s *openapi3.Schema, depth int) interface{} {
	if depth > 5 || s == nil {
		return nil
	}
	if s.Example != nil {
		return s.Example
	}
	if s.Default != nil {
		return s.Default
	}
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	if s.Type == nil {
		return nil
	}
	switch {
	case s.Type.Is("object"):
		obj := map[string]interface{}{}
		for name, propRef := range s.Properties {
			if propRef.Value == nil {
				continue
			}
			obj[name] = generateFromSchema(propRef.Value, depth+1)
		}
		return obj
	case s.Type.Is("array"):
		if s.Items != nil && s.Items.Value != nil {
			return []interface{}{generateFromSchema(s.Items.Value, depth+1)}
		}
		return []interface{}{}
	case s.Type.Is("integer"), s.Type.Is("number"):
		return 1
	case s.Type.Is("boolean"):
		return false
	default:
		return "x"
	}
}

func urlValuesToMap(v url.Values) map[string]string {
	out := map[string]string{}
	for k, vs := range v {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}
