package threagile

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Pinguladora/threagile/pkg/types"
	"gopkg.in/yaml.v3"
)

// These tests keep support/schema.json, which editors use to validate and complete models, in
// line with what threagile itself accepts. go.mod has no JSON-schema validator, so
// validateSchema below implements the keywords the schema uses, and those of the OTM schema that
// otm_schema_test.go checks the OTM output against.

const draft07MetaSchema = "http://json-schema.org/draft-07/schema#"

// schemaEnumTypes names the Go values of every enum in the schema, by the path of the enum with
// map keys and list indexes replaced by "*"; each enum must list exactly the names of the values,
// which are what the Parse functions accept.
var schemaEnumTypes = map[string][]types.TypeEnum{
	"business_criticality":                                                types.CriticalityValues(),
	"data_assets/*/availability":                                          types.CriticalityValues(),
	"data_assets/*/confidentiality":                                       types.ConfidentialityValues(),
	"data_assets/*/integrity":                                             types.CriticalityValues(),
	"data_assets/*/quantity":                                              types.QuantityValues(),
	"data_assets/*/usage":                                                 types.UsageValues(),
	"risk_tracking/*/status":                                              types.RiskStatusValues(),
	"technical_assets/*/availability":                                     types.CriticalityValues(),
	"technical_assets/*/communication_links/*/authentication":             types.AuthenticationValues(),
	"technical_assets/*/communication_links/*/authorization":              types.AuthorizationValues(),
	"technical_assets/*/communication_links/*/protocol":                   types.ProtocolValues(),
	"technical_assets/*/communication_links/*/usage":                      types.UsageValues(),
	"technical_assets/*/confidentiality":                                  types.ConfidentialityValues(),
	"technical_assets/*/data_formats_accepted/*":                          types.DataFormatValues(),
	"technical_assets/*/encryption":                                       types.EncryptionStyleValues(),
	"technical_assets/*/integrity":                                        types.CriticalityValues(),
	"technical_assets/*/machine":                                          types.TechnicalAssetMachineValues(),
	"technical_assets/*/size":                                             types.TechnicalAssetSizeValues(),
	"technical_assets/*/technologies/*":                                   types.TechnicalAssetTechnologyValues(defaultTechnologies{}),
	"technical_assets/*/technology":                                       types.TechnicalAssetTechnologyValues(defaultTechnologies{}),
	"technical_assets/*/usage":                                            types.UsageValues(),
	"technical_assets/*/type":                                             types.TechnicalAssetTypeValues(),
	"trust_boundaries/*/type":                                             types.TrustBoundaryTypeValues(),
	"custom_risk_categories/*/function":                                   types.RiskFunctionValues(),
	"custom_risk_categories/*/stride":                                     types.STRIDEValues(),
	"custom_risk_categories/*/risks_identified/*/severity":                types.RiskSeverityValues(),
	"custom_risk_categories/*/risks_identified/*/exploitation_impact":     types.RiskExploitationImpactValues(),
	"custom_risk_categories/*/risks_identified/*/exploitation_likelihood": types.RiskExploitationLikelihoodValues(),
	"custom_risk_categories/*/risks_identified/*/data_breach_probability": types.DataBreachProbabilityValues(),
}

// schemaEnumsWithoutGoType are enums of plain strings that the diagram code checks itself.
var schemaEnumsWithoutGoType = map[string][]string{
	"diagram_tweak_edge_layout": {"", "ortho", "spline", "polyline", "false", "curved"},
}

type defaultTechnologies struct{}

func (defaultTechnologies) GetAppFolder() string { return "" }

func (defaultTechnologies) GetTechnologyFilename() string { return "" }

func TestSchemaUsesStandardMetaSchema(t *testing.T) {
	schema := readSchema(t)

	if schema["$schema"] != draft07MetaSchema {
		t.Errorf("$schema is %q, want the JSON-Schema meta-schema %q (threagile#41)", schema["$schema"], draft07MetaSchema)
	}

	if _, ok := schema["id"]; ok {
		t.Error(`draft-07 names the schema with "$id", not "id"`)
	}

	if id, ok := schema["$id"].(string); ok && !strings.HasPrefix(id, "https://") {
		t.Errorf("$id %q is not an absolute https URL", id)
	}
}

func TestSchemaEnumsMatchGoTypes(t *testing.T) {
	schema := readSchema(t)
	enums := make(map[string][]string)
	collectSchemaEnums(schema, schema, "", enums)

	for _, enumPath := range slices.Sorted(maps.Keys(enums)) {
		values := enums[enumPath]
		if want, ok := schemaEnumsWithoutGoType[enumPath]; ok {
			if !slices.Equal(values, want) {
				t.Errorf("schema enum %s is %q, want %q", enumPath, values, want)
			}

			continue
		}

		// the deprecated individual_risk_categories map shares its definition with the list
		goValues, ok := schemaEnumTypes[strings.Replace(enumPath, "individual_risk_categories/", "custom_risk_categories/", 1)]
		if !ok {
			t.Errorf("schema enum %s has no Go type in schemaEnumTypes", enumPath)
			continue
		}

		goNames := make([]string, 0, len(goValues))
		for _, value := range goValues {
			goNames = append(goNames, value.String())
		}

		for _, value := range values {
			if !slices.Contains(goNames, value) {
				t.Errorf("schema enum %s lists %q, which threagile does not accept", enumPath, value)
			}
		}

		for _, name := range goNames {
			if !slices.Contains(values, name) {
				t.Errorf("schema enum %s lacks %q", enumPath, name)
			}
		}
	}

	for _, enumPath := range slices.Sorted(maps.Keys(schemaEnumTypes)) {
		if _, ok := enums[enumPath]; !ok {
			t.Errorf("schemaEnumTypes names %s, which is not an enum in the schema", enumPath)
		}
	}
}

func TestBundledModelsMatchSchema(t *testing.T) {
	schema := readSchema(t)

	for _, model := range []Asset{ExampleModel, StubModel} {
		var document any
		if err := yaml.Unmarshal(model.Bytes(), &document); err != nil {
			t.Fatalf("parsing %s: %v", model, err)
		}

		for _, problem := range validateSchema(schema, schema, document, "") {
			t.Errorf("%s: %s", model, problem)
		}

		// the schema allows other keys, but threagile ignores them: here they are a mistake, like
		// the renamed individual_risk_categories was
		properties, _ := schema["properties"].(map[string]any)
		topLevel, _ := document.(map[string]any)
		for _, key := range slices.Sorted(maps.Keys(topLevel)) {
			if _, ok := properties[key]; !ok {
				t.Errorf("%s: key %q is not in the schema", model, key)
			}
		}
	}
}

func TestSchemaValidatorFindsProblems(t *testing.T) {
	schema := readSchema(t)
	document := map[string]any{
		"title": "Broken",
		"technical_assets": map[string]any{
			"Asset": map[string]any{"machine": "mainframe", "communication_links": map[string]any{
				"Link": map[string]any{"authorization": "everyone"},
			}},
		},
	}

	problems := strings.Join(validateSchema(schema, schema, document, ""), "\n")
	for _, want := range []string{
		`/: missing required property "author"`,
		`/technical_assets/Asset/machine: "mainframe" is not one of`,
		`/technical_assets/Asset/communication_links/Link/authorization: "everyone" is not one of`,
		`/technical_assets/Asset: missing required property "id"`,
		`/technical_assets/Asset: matches none of anyOf`,
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("want a problem %q, got:\n%s", want, problems)
		}
	}
}

// TestSchemaDescribesVia validates the model with a via list that the risk rules are tested with
// (threagile#15), and a via list that is not a list of asset ids.
func TestSchemaDescribesVia(t *testing.T) {
	schema := readSchema(t)

	data, err := os.ReadFile("pkg/risks/testdata/via-links/threagile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parsing the model: %v", err)
	}
	for _, problem := range validateSchema(schema, schema, document, "") {
		t.Error(problem)
	}

	broken := map[string]any{"technical_assets": map[string]any{
		"Asset": map[string]any{"communication_links": map[string]any{
			"Link": map[string]any{"via": "waf"},
		}},
	}}
	problems := strings.Join(validateSchema(schema, schema, broken, ""), "\n")
	if want := "/technical_assets/Asset/communication_links/Link/via:"; !strings.Contains(problems, want) {
		t.Errorf("want a problem %q, got:\n%s", want, problems)
	}
}

func TestSchemaValidatorChecksOneOf(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal([]byte(`{"type": "object", "oneOf": [{"required": ["a"]}, {"required": ["b"]}]}`), &schema); err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		document map[string]any
		want     string
	}{
		{map[string]any{"a": 1}, ""},
		{map[string]any{"b": 1}, ""},
		{map[string]any{}, "/: matches 0 of oneOf, want exactly 1"},
		{map[string]any{"a": 1, "b": 1}, "/: matches 2 of oneOf, want exactly 1"},
	} {
		if got := strings.Join(validateSchema(schema, schema, check.document, ""), "\n"); got != check.want {
			t.Errorf("%v: got %q, want %q", check.document, got, check.want)
		}
	}
}

func readSchema(t *testing.T) map[string]any {
	t.Helper()

	var schema map[string]any
	if err := json.Unmarshal(Schema.Bytes(), &schema); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}

	return schema
}

// collectSchemaEnums records the enum of node and of every schema below it by instance path.
func collectSchemaEnums(root map[string]any, node map[string]any, instancePath string, enums map[string][]string) {
	node = resolveRef(root, node)

	if values, ok := node["enum"].([]any); ok {
		names := make([]string, 0, len(values))
		for _, value := range values {
			names = append(names, fmt.Sprint(value))
		}

		enums[strings.TrimPrefix(instancePath, "/")] = names
	}

	if properties, ok := node["properties"].(map[string]any); ok {
		for name, property := range properties {
			if propertySchema, ok := property.(map[string]any); ok {
				collectSchemaEnums(root, propertySchema, instancePath+"/"+name, enums)
			}
		}
	}

	for _, keyword := range []string{"additionalProperties", "items"} {
		if child, ok := node[keyword].(map[string]any); ok {
			collectSchemaEnums(root, child, instancePath+"/*", enums)
		}
	}
}

// resolveRef follows a "$ref" to a definition in the same document.
func resolveRef(root map[string]any, node map[string]any) map[string]any {
	ref, ok := node["$ref"].(string)
	if !ok {
		return node
	}

	resolved := any(root)
	for part := range strings.SplitSeq(strings.TrimPrefix(ref, "#/"), "/") {
		object, isObject := resolved.(map[string]any)
		if !isObject {
			return nil
		}
		resolved = object[part]
	}

	resolvedNode, _ := resolved.(map[string]any)
	return resolvedNode
}

// validateSchema checks document against node, a schema in root, for the keywords the schema uses
// (format is not checked), and returns the problems found.
func validateSchema(root map[string]any, node map[string]any, document any, instancePath string) []string {
	node = resolveRef(root, node)
	if node == nil {
		return []string{instancePath + ": unresolvable $ref"}
	}

	location := instancePath
	if location == "" {
		location = "/"
	}

	if typeProblem := checkType(node["type"], document); typeProblem != "" {
		return []string{location + ": " + typeProblem}
	}

	var problems []string
	if values, ok := node["enum"].([]any); ok && !slices.Contains(values, document) {
		problems = append(problems, fmt.Sprintf("%s: %q is not one of %v", location, document, values))
	}

	for _, subSchema := range schemaList(node["allOf"]) {
		problems = append(problems, validateSchema(root, subSchema, document, instancePath)...)
	}

	if anyOf := schemaList(node["anyOf"]); len(anyOf) > 0 && !slices.ContainsFunc(anyOf, func(subSchema map[string]any) bool {
		return len(validateSchema(root, subSchema, document, instancePath)) == 0
	}) {
		problems = append(problems, location+": matches none of anyOf")
	}

	if oneOf := schemaList(node["oneOf"]); len(oneOf) > 0 {
		matches := 0
		for _, subSchema := range oneOf {
			if len(validateSchema(root, subSchema, document, instancePath)) == 0 {
				matches++
			}
		}

		if matches != 1 {
			problems = append(problems, fmt.Sprintf("%s: matches %d of oneOf, want exactly 1", location, matches))
		}
	}

	switch value := document.(type) {
	case map[string]any:
		problems = append(problems, validateObject(root, node, value, instancePath, location)...)

	case []any:
		if items, ok := node["items"].(map[string]any); ok {
			for index, item := range value {
				problems = append(problems, validateSchema(root, items, item, fmt.Sprintf("%s/%d", instancePath, index))...)
			}
		}
	}

	return problems
}

func validateObject(root map[string]any, node map[string]any, object map[string]any, instancePath string, location string) []string {
	var problems []string
	for _, required := range schemaStrings(node["required"]) {
		if _, ok := object[required]; !ok {
			problems = append(problems, fmt.Sprintf("%s: missing required property %q", location, required))
		}
	}

	properties, _ := node["properties"].(map[string]any)
	for _, name := range slices.Sorted(maps.Keys(object)) {
		childPath := instancePath + "/" + name
		if property, ok := properties[name].(map[string]any); ok {
			problems = append(problems, validateSchema(root, property, object[name], childPath)...)
			continue
		}

		switch additional := node["additionalProperties"].(type) {
		case map[string]any:
			problems = append(problems, validateSchema(root, additional, object[name], childPath)...)
		case bool:
			if !additional {
				problems = append(problems, fmt.Sprintf("%s: property %q is not allowed", location, name))
			}
		}
	}

	return problems
}

// checkType returns a problem when value does not have one of the JSON types in schemaType.
func checkType(schemaType any, value any) string {
	allowed := schemaStrings(schemaType)
	if name, ok := schemaType.(string); ok {
		allowed = []string{name}
	}

	if len(allowed) == 0 {
		return ""
	}

	var actual string
	switch typed := value.(type) {
	case nil:
		actual = "null"
	case bool:
		actual = "boolean"
	case int, int64, uint64:
		actual = "integer"
	case float64:
		actual = "number"
		if typed == float64(int64(typed)) && slices.Contains(allowed, "integer") {
			actual = "integer"
		}
	case string, time.Time:
		// YAML decodes an unquoted date to a time; in JSON it is a string
		actual = "string"
	case []any:
		actual = "array"
	case map[string]any:
		actual = "object"
	default:
		actual = fmt.Sprintf("%T", value)
	}

	if slices.Contains(allowed, actual) || (actual == "integer" && slices.Contains(allowed, "number")) {
		return ""
	}

	return fmt.Sprintf("is %s, want %s", actual, strings.Join(allowed, " or "))
}

func schemaList(value any) []map[string]any {
	list, _ := value.([]any)
	result := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if itemSchema, ok := item.(map[string]any); ok {
			result = append(result, itemSchema)
		}
	}

	return result
}

func schemaStrings(value any) []string {
	list, _ := value.([]any)
	result := make([]string, 0, len(list))
	for _, item := range list {
		result = append(result, fmt.Sprint(item))
	}

	return result
}
