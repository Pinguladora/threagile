package report

import (
	"testing"

	"github.com/Pinguladora/threagile/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestMarkdownText(t *testing.T) {
	for _, test := range []struct{ text, want string }{
		{"plain text", "plain text"},
		{"  spaced \t\r\n out\x00 ", "spaced out"},
		{`<script>alert("x")</script>`, `&lt;script&gt;alert("x")&lt;/script&gt;`},
		{"R&D &lt;", "R&amp;D &amp;lt;"},
		{"a | b", "a &#124; b"},
		{"*bold* _it_ `code` ~~strike~~ $math$", "\\*bold\\* \\_it\\_ \\`code\\` &#126;&#126;strike&#126;&#126; &#36;math&#36;"},
		{"[link](javascript:alert(1)) ![image](x)", `\[link\](javascript:alert(1)) !\[image\](x)`},
		{`{: onclick="x"} {props.x}`, `\{: onclick="x"\} \{props.x\}`},
		{`C# \ path`, `C\# \\ path`},
		{"customer_data _leading trailing_ a__b", `customer_data \_leading trailing\_ a\_\_b`},
	} {
		assert.Equal(t, test.want, markdownText(test.text), test.text)
	}
}

func TestMarkdownBlockStart(t *testing.T) {
	for _, test := range []struct{ line, want string }{
		{"text", "text"},
		{"- item", `\- item`},
		{"+ item", `\+ item`},
		{"!!! warning", `\!!! warning`},
		{"=== tab", "&#61;== tab"},
		{"??? note", "&#63;?? note"},
		{"::: danger", "&#58;:: danger"},
		{"1. first", `1\. first`},
		{"2024) year", `2024\) year`},
		{"2024 year", "2024 year"},
		{"export const x = 1", "&#101;xport const x = 1"},
		{"import x from 'y'", "&#105;mport x from 'y'"},
		{"important", "important"},
		{"", ""},
	} {
		assert.Equal(t, test.want, markdownBlockStart(test.line), test.line)
	}
}

func TestMarkdownMarkup(t *testing.T) {
	for _, test := range []struct {
		text string
		want []string
	}{
		{"plain & simple", []string{"plain &amp; simple"}},
		{"<b>bold</b>, <i>italic</i> and <u>underlined</u><br>next", []string{"**bold**, _italic_ and _underlined_", "next"}},
		{"<b> spaced </b>out", []string{"**spaced** out"}},
		{"<b>a <i>b</i></b> c", []string{"**a _b_** c"}},
		{"<b>a<i>b</i></b>c", []string{"**a_b_**c"}},
		{"<b><i>both</i></b>", []string{"**_both_**"}},
		{"<b>mis <i>nest</b> ed</i>", []string{"**mis _nest_** _ed_"}},
		{"<b>never closed", []string{"**never closed**"}},
		{"closed </b> but never opened", []string{"closed &lt;/b&gt; but never opened"}},
		{"<b>*not* <b>twice</b></b>", []string{`**\*not\* twice**`}},
		{"<script>alert(1)</script>", []string{"&lt;script&gt;alert(1)&lt;/script&gt;"}},
		{"first<br><br><br>second<br>", []string{"first", "second"}},
		{"<b> </b>", nil},
		{`see <a href="https://example.com/a b">this</a>.`, []string{"see [this](https://example.com/a%20b)."}},
		{`<a href="javascript:alert(1)">text</a> stays`, []string{"text stays"}},
		{`<a href="https://example.com"><b>bold</b> link</a>`, []string{"[**bold** link](https://example.com)"}},
		{`<a href="https://example.com"></a>empty`, []string{"empty"}},
	} {
		lines := markdownLines(markupText(test.text), true)
		if test.want == nil {
			assert.Empty(t, lines, test.text)
		} else {
			assert.Equal(t, test.want, lines, test.text)
		}
	}
	// links leave out the links in their text, which Markdown cannot nest
	assert.Equal(t, []string{"**bold** link"}, markdownLines(`<a href="https://example.com"><b>bold</b> link</a>`, false))
	assert.Equal(t, "one two", markdownInline("one<br>two"))
}

func TestMarkdownURL(t *testing.T) {
	assert.Equal(t, "https://example.com/a%20b%28c%29%7Cd%5C%22%3C%3E%60%7B%7D%5B%5D%C3%A9?x=1&y=2#f",
		markdownURL("https://example.com/a b(c)|d\\\"<>`{}[]é?x=1&y=2#f"))
}

func TestMarkdownCode(t *testing.T) {
	assert.Equal(t, "`a@b>c`", markdownCode("a@b>c"))
	assert.Equal(t, "a\\`b", markdownCode("a`b"))
	assert.Equal(t, "a &#124; b", markdownCode("a | b"))
	assert.Equal(t, "a b", markdownCode("a\nb"))
	assert.Empty(t, markdownCode(""))
}

func TestHeadingSlugs(t *testing.T) {
	slugs := make(headingSlugs)
	for _, test := range []struct{ heading, want string }{
		{"Management Summary", "management-summary"},
		{"SQL/NoSQL-Injection", "sqlnosql-injection"},
		{"Missing Two-Factor Authentication (2FA)", "missing-two-factor-authentication-2fa"},
		{"A - B", "a---b"},
		{"snake_case & Ünïcödé", "snake_case--ünïcödé"},
		{"Database Traffic", "database-traffic"},
		{"Database Traffic", "database-traffic-1"},
		{"database-traffic-2", "database-traffic-2"},
		{"Database Traffic", "database-traffic-3"},
		{"<script>", "script"},
		{"???", ""},
	} {
		assert.Equal(t, test.want, slugs.next(test.heading), test.heading)
	}
}

func TestMermaidLabel(t *testing.T) {
	assert.Equal(t, `"a #quot;b#quot; #35;quot#59; #96;x#96; #lt;script#gt; #amp;amp#59; #124; [c] (d) {e}"`,
		mermaidLabel("a \"b\" #quot; `x` <script> &amp; | [c] (d) {e}"))
	assert.Equal(t, `"two lines"`, mermaidLabel("two\nlines"))
	assert.Equal(t, `" "`, mermaidLabel(""))
}

func TestMermaidNodeIDs(t *testing.T) {
	// costarring and liquid share their FNV-1a hash
	ids := mermaidNodeIDs("ta_", []string{"liquid", "costarring", "other", `"><script>`})
	assert.Equal(t, "ta_"+hash("costarring"), ids["costarring"])
	assert.Equal(t, "ta_"+hash("costarring")+"_2", ids["liquid"])
	assert.Regexp(t, `^ta_\d+$`, ids[`"><script>`])
	assert.Len(t, ids, 4)
}

func TestMermaidNodeShapes(t *testing.T) {
	assert.Equal(t, `n["E"]`, mermaidNode("n", &types.TechnicalAsset{Title: "E", Type: types.ExternalEntity}))
	assert.Equal(t, `n(["P"])`, mermaidNode("n", &types.TechnicalAsset{Title: "P", Type: types.Process}))
	assert.Equal(t, `n[("D")]`, mermaidNode("n", &types.TechnicalAsset{Title: "D", Type: types.Datastore}))
	assert.Equal(t, `n{{"C"}}`, mermaidNode("n", &types.TechnicalAsset{Title: "C", Type: types.Process, UsedAsClientByHuman: true}))
}

// TestMarkdownChapters checks that every chapter of the report has a writer.
func TestMarkdownChapters(t *testing.T) {
	assert.Len(t, markdownChapters, len(viewChapters))
	for _, chapter := range viewChapters {
		assert.NotNil(t, markdownChapters[chapter.ID], chapter.ID)
	}
}
