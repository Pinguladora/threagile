package threagile

// ValidateSchema lets the tests of package threagile_test, which can use the packages that import
// this one, validate documents against a JSON schema.
var ValidateSchema = func(schema map[string]any, document any) []string {
	return validateSchema(schema, schema, document, "")
}
