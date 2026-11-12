package model

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
	"go.yaml.in/yaml/v4"
)

// Migration is what MigrateModelFile changed in a model file and the files it includes, and what it left for the
// author to decide.
type Migration struct {
	Changes []string // the changes, per file and link
	Notes   []string // what to review by hand

	identitiesMoved int
}

// valuesCommentPrefix starts the comments that list the values of a field, like those of the example model.
const valuesCommentPrefix = "# values:"

// MigrateModelFile rewrites a model file of an earlier version, and the files it includes, to the current fields:
// it moves the identity that the authorization of a communication link held into its identity, leaving the
// authorization unknown, renames two-factor authentication to multi-factor, and turns individual_risk_categories
// into custom_risk_categories. It edits only the lines it
// changes, so comments and layout stay as they are, and updates comments listing the values of a field. Links
// authenticated with token are left for the author to choose short-lived-token or long-lived-token.
func MigrateModelFile(filename string) (*Migration, error) {
	migration := new(Migration)
	err := migration.migrate(filepath.Clean(filename), make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if migration.identitiesMoved > 0 {
		migration.Notes = append(migration.Notes, fmt.Sprintf("set the authorization of the %d links whose "+
			"identity moved (none, authenticated-only, function-level or object-level)", migration.identitiesMoved))
	}
	return migration, nil
}

func (what *Migration) migrate(filename string, visited map[string]bool) error {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("unable to resolve %q: %w", filename, err)
	}
	if visited[absolute] {
		return nil
	}
	visited[absolute] = true

	content, err := os.ReadFile(filename) // #nosec G304 // the model file the user names
	if err != nil {
		return fmt.Errorf("unable to read %q: %w", filename, err)
	}
	var document yaml.Node
	if err = yaml.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("unable to parse %q: %w", filename, err)
	}
	if len(document.Content) == 0 {
		return nil
	}
	root := document.Content[0]

	file := &fileMigration{name: filename, lines: strings.SplitAfter(string(content), "\n"), migration: what}
	file.migrateTechnicalAssets(mappingValue(root, "technical_assets"))
	file.migrateIndividualRiskCategories(root)
	if len(file.edits) > 0 {
		if err = os.WriteFile(filename, file.apply(), 0o600); err != nil {
			return fmt.Errorf("unable to write %q: %w", filename, err)
		}
	}

	for _, include := range sequenceValues(mappingValue(root, "includes")) {
		if err = what.migrate(filepath.Join(filepath.Dir(filename), include), visited); err != nil {
			return err
		}
	}
	return nil
}

// fileMigration collects the line edits of one model file.
type fileMigration struct {
	name      string
	lines     []string
	edits     map[int][]string // replacement lines by the index of the line they replace
	migration *Migration
}

func (what *fileMigration) migrateTechnicalAssets(technicalAssets *yaml.Node) {
	for _, asset := range mappingPairs(technicalAssets) {
		usedByHumans := mappingValue(asset.value, "used_as_client_by_human")
		for _, link := range mappingPairs(mappingValue(asset.value, "communication_links")) {
			where := fmt.Sprintf("%s: technical asset %q communication link %q", what.name, asset.key.Value,
				link.key.Value)
			what.migrateLink(where, link.value, usedByHumans != nil && usedByHumans.Value == "true")
		}
	}
}

// migrateLink migrates a communication link of a technical asset, which may be a client that humans use.
func (what *fileMigration) migrateLink(where string, link *yaml.Node, usedByHumans bool) {
	if link == nil || link.Kind != yaml.MappingNode {
		return
	}
	if link.Style&yaml.FlowStyle != 0 {
		what.migration.Notes = append(what.migration.Notes, where+": written in flow style, migrate it by hand")
		return
	}

	what.migrateAuthentication(where, mappingPair(link, "authentication"))

	authorization := mappingPair(link, "authorization")
	if authorization == nil || mappingPair(link, "identity") != nil {
		return
	}
	identity, isLegacy := types.LegacyIdentity(authorization.value.Value)
	if !isLegacy {
		return
	}
	if what.replaceWithIdentity(where, authorization, identity) {
		what.migration.Changes = append(what.migration.Changes, fmt.Sprintf("%s: authorization %s is now identity "+
			"%s, authorization unknown", where, authorization.value.Value, identity))
		what.migration.identitiesMoved++
		if usedByHumans && identity == types.ServiceAccount {
			what.migration.Notes = append(what.migration.Notes, where+": the caller is used by humans, set the "+
				"identity to end-user if they sign in with their own accounts")
		}
	}
}

// migrateAuthentication renames two-factor to multi-factor, notes a token whose lifetime is open, and updates a
// comment listing the values of the authentication.
func (what *fileMigration) migrateAuthentication(where string, authentication *pair) {
	if authentication == nil {
		return
	}
	values := valueNames(types.AuthenticationValues())
	switch strings.ToLower(authentication.value.Value) {
	case "two-factor":
		if what.replace(where, authentication, types.MultiFactor.String(), values) {
			what.migration.Changes = append(what.migration.Changes, where+": authentication two-factor is now "+
				"multi-factor")
		}
		return
	case types.Token.String():
		what.migration.Notes = append(what.migration.Notes, where+": authentication token, choose "+
			"short-lived-token or long-lived-token")
	}
	what.updateValuesComment(where, authentication, values)
}

// migrateIndividualRiskCategories turns the deprecated individual_risk_categories, a mapping of risk categories by
// title, into custom_risk_categories, a sequence of risk categories with a title each. It changes the line of the key
// and the line of the title of each category, so the fields of the categories stay as they are; it leaves layouts
// that this cannot rewrite, and models that have both keys, to the author.
func (what *fileMigration) migrateIndividualRiskCategories(root *yaml.Node) {
	individual := mappingPair(root, "individual_risk_categories")
	if individual == nil {
		return
	}
	where := what.name + ": individual_risk_categories"
	if mappingPair(root, "custom_risk_categories") != nil {
		what.migration.Notes = append(what.migration.Notes, where+": the model has custom_risk_categories as well, "+
			"move the categories into it by hand")
		return
	}
	categories := mappingPairs(individual.value)
	if individual.value.Style&yaml.FlowStyle != 0 || !allCategoriesOnLinesOfTheirOwn(categories) {
		what.migration.Notes = append(what.migration.Notes, where+": not in the layout of the example model, "+
			"migrate it by hand")
		return
	}

	keyLine, ok := what.keyLine(where, individual.key)
	if !ok {
		return
	}
	edits := map[int]string{keyLine: "custom_risk_categories:"}
	for _, category := range categories {
		line, found := what.keyLine(where, category.key)
		if !found {
			return
		}
		item := "- title: " + yamlScalar(category.key.Value)
		if mappingPair(category.value, "title") != nil {
			item = "-" // the category names its title itself
		}
		edits[line] = item
	}
	for line, replacement := range edits {
		what.edits[line] = []string{replacedKeyLine(what.lines[line], replacement)}
	}
	what.migration.Changes = append(what.migration.Changes, fmt.Sprintf("%s: now custom_risk_categories, %d "+
		"categories", where, len(categories)))
}

// allCategoriesOnLinesOfTheirOwn reports whether each category is a block mapping that starts on the line after its
// title, indented by two columns more, so that a sequence item of the title holds its fields as they are.
func allCategoriesOnLinesOfTheirOwn(categories []pair) bool {
	const itemIndent = 2 // the "- " of a sequence item
	for _, category := range categories {
		fields := category.value
		if category.key.Style != 0 || fields.Kind != yaml.MappingNode || fields.Style&yaml.FlowStyle != 0 ||
			len(fields.Content) == 0 || fields.Content[0].Line == category.key.Line ||
			fields.Content[0].Column != category.key.Column+itemIndent {
			return false
		}
	}
	return true
}

// keyLine returns the index of the line of a key whose value starts on the following lines, and makes sure that
// edits can be made.
func (what *fileMigration) keyLine(where string, key *yaml.Node) (int, bool) {
	line := key.Line - 1
	if line >= len(what.lines) || !strings.HasPrefix(strings.TrimSpace(what.lines[line]), key.Value+":") {
		what.migration.Notes = append(what.migration.Notes, fmt.Sprintf("%s: %s is not on a plain line of its "+
			"own, migrate it by hand", where, key.Value))
		return 0, false
	}
	if what.edits == nil {
		what.edits = make(map[int][]string)
	}
	return line, true
}

// replacedKeyLine replaces the key of a line, keeping its indentation and what follows the colon, like a comment.
func replacedKeyLine(line string, replacement string) string {
	indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
	rest := line[strings.Index(line, ":")+1:]
	if !strings.HasSuffix(rest, "\n") {
		rest += "\n"
	}
	return indent + replacement + rest
}

// yamlScalar writes the text as a YAML scalar, quoted where YAML needs it.
func yamlScalar(text string) string {
	encoded, err := yaml.Marshal(text)
	if err != nil {
		return strconv.Quote(text)
	}
	return strings.TrimSuffix(string(encoded), "\n")
}

// replaceWithIdentity replaces the line of the authorization with a line of the identity and one of an unknown
// authorization. A comment that is no list of values was about the identity, so it stays with the identity.
func (what *fileMigration) replaceWithIdentity(where string, authorization *pair, identity types.Identity) bool {
	line, ok := what.lineOf(where, authorization)
	if !ok {
		return false
	}
	indent := strings.Repeat(" ", authorization.key.Column-1)
	comment := authorization.value.LineComment
	what.edits[line] = []string{
		indent + "identity: " + identity.String() + valuesComment(comment, valueNames(types.IdentityValues())) + "\n",
		indent + "authorization: " + types.UnknownAuthorization.String() +
			valuesListComment(comment, valueNames(types.AuthorizationValues())) + "\n",
	}
	return true
}

// updateValuesComment updates a comment listing the values of the field when it lists others than the current ones.
func (what *fileMigration) updateValuesComment(where string, field *pair, values []string) {
	comment := field.value.LineComment
	if !strings.HasPrefix(comment, valuesCommentPrefix) || strings.TrimSpace(valuesComment(comment, values)) == comment {
		return
	}
	what.replace(where, field, field.value.Value, values)
}

// replace replaces the value of the pair on its line, and the values of its comment.
func (what *fileMigration) replace(where string, field *pair, value string, values []string) bool {
	line, ok := what.lineOf(where, field)
	if !ok {
		return false
	}
	indent := strings.Repeat(" ", field.key.Column-1)
	what.edits[line] = []string{
		indent + field.key.Value + ": " + value +
			valuesComment(field.value.LineComment, values) + "\n",
	}
	return true
}

// lineOf returns the index of the line of a field that has its key and its plain value on one line of its own.
func (what *fileMigration) lineOf(where string, field *pair) (int, bool) {
	line := field.key.Line - 1
	if field.value.Line != field.key.Line || field.value.Style != 0 || line >= len(what.lines) ||
		!strings.HasPrefix(strings.TrimSpace(what.lines[line]), field.key.Value+":") {
		what.migration.Notes = append(what.migration.Notes, fmt.Sprintf("%s: %s is not on a plain line of its "+
			"own, migrate it by hand", where, field.key.Value))
		return 0, false
	}
	if what.edits == nil {
		what.edits = make(map[int][]string)
	}
	return line, true
}

func (what *fileMigration) apply() []byte {
	var result bytes.Buffer
	for index, line := range what.lines {
		if replacement, ok := what.edits[index]; ok {
			if !strings.HasSuffix(line, "\n") { // the last line of a file without a final newline
				replacement[len(replacement)-1] = strings.TrimSuffix(replacement[len(replacement)-1], "\n")
			}
			result.WriteString(strings.Join(replacement, ""))
			continue
		}
		result.WriteString(line)
	}
	return result.Bytes()
}

// valuesComment returns the line comment to write: a list of the values when the comment was one, and the
// comment as it was otherwise.
func valuesComment(comment string, values []string) string {
	if comment == "" {
		return ""
	}
	if strings.HasPrefix(comment, valuesCommentPrefix) {
		return " " + valuesCommentPrefix + " " + strings.Join(values, ", ")
	}
	return " " + comment
}

// valuesListComment returns a list of the values when the comment was one, and no comment otherwise.
func valuesListComment(comment string, values []string) string {
	if !strings.HasPrefix(comment, valuesCommentPrefix) {
		return ""
	}
	return valuesComment(comment, values)
}

func valueNames(values []types.TypeEnum) []string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, value.String())
	}
	return names
}

// pair is a key and its value in a mapping node.
type pair struct {
	key, value *yaml.Node
}

func mappingPairs(mapping *yaml.Node) []pair {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	const nodesPerPair = 2 // a key and its value
	pairs := make([]pair, 0, len(mapping.Content)/nodesPerPair)
	for index := 0; index+1 < len(mapping.Content); index += nodesPerPair {
		pairs = append(pairs, pair{key: mapping.Content[index], value: mapping.Content[index+1]})
	}
	return pairs
}

func mappingPair(mapping *yaml.Node, key string) *pair {
	pairs := mappingPairs(mapping)
	index := slices.IndexFunc(pairs, func(candidate pair) bool { return candidate.key.Value == key })
	if index < 0 {
		return nil
	}
	return &pairs[index]
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if found := mappingPair(mapping, key); found != nil {
		return found.value
	}
	return nil
}

func sequenceValues(sequence *yaml.Node) []string {
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return nil
	}
	values := make([]string, 0, len(sequence.Content))
	for _, item := range sequence.Content {
		values = append(values, item.Value)
	}
	return values
}
