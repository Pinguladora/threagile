package report

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicMarkup(t *testing.T) {
	for _, test := range []struct{ text, want string }{
		{"plain & simple", "plain &amp; simple"},
		{"<b>bold</b>, <i>italic</i> and <u>underlined</u><br>next", "<b>bold</b>, <i>italic</i> and <u>underlined</u><br>next"},
		{"<b>never closed", "<b>never closed</b>"},
		{"closed </b> but never opened", "closed &lt;/b&gt; but never opened"},
		{"<b>mis<i>nest</b>ed</i>", "<b>mis<i>nest</i></b><i>ed</i>"},
		{"<b><b>twice</b></b>", "<b><b>twice</b></b>"},
		{`<b class="x">attributes</b>`, "&lt;b class=&#34;x&#34;&gt;attributes&lt;/b&gt;"},
		{"<B>upper case</B>", "&lt;B&gt;upper case&lt;/B&gt;"},
		{"<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"<br/> and <br >", "&lt;br/&gt; and &lt;br &gt;"},
		{"<EMAIL ADDRESS>", "&lt;EMAIL ADDRESS&gt;"},
		{
			`see <a href="https://example.com/a?b=1&amp;c=2">this</a>`,
			`see <a href="https://example.com/a?b=1&amp;c=2" rel="noopener noreferrer">this</a>`,
		},
		{
			`<a href="http://example.com"><b>bold</a> link</b>`,
			`<a href="http://example.com" rel="noopener noreferrer"><b>bold</b></a><b> link</b>`,
		},
		{`<a href="javascript:alert(1)">text</a> stays`, "text stays"},
		{`<a href="JavaScript:alert(1)">text</a>`, "text"},
		{`<a href="//example.com">relative</a>`, "relative"},
		{`<a href="data:text/html,x">data</a>`, "data"},
		{
			`<a href="https://example.com" onclick="x">attributes</a>`,
			"&lt;a href=&#34;https://example.com&#34; onclick=&#34;x&#34;&gt;attributes&lt;/a&gt;",
		},
		{
			`<a href="https://a.example"><a href="https://b.example">nested</a></a>`,
			`<a href="https://a.example" rel="noopener noreferrer">&lt;a href=&#34;https://b.example&#34;&gt;nested</a>&lt;/a&gt;`,
		},
		{`<a href="https://example.com">never closed`, `<a href="https://example.com" rel="noopener noreferrer">never closed</a>`},
		{
			`<a href="https://example.com/&quot;onmouseover=x">quote</a>`,
			`<a href="https://example.com/%22onmouseover=x" rel="noopener noreferrer">quote</a>`,
		},
	} {
		assert.Equal(t, test.want, string(basicMarkup(test.text)), test.text)
	}
}

func TestHTTPLink(t *testing.T) {
	for link, want := range map[string]bool{
		"https://example.com/x": true, "http://example.com": true, "\thttps://example.com\n": true,
		"HTTPS://EXAMPLE.COM": true, "javascript:alert(1)": false, "mailto:a@example.com": false,
		"//example.com": false, "/relative": false, "https://": false, "": false, "ftp://example.com": false,
		"https://[::1]:8080/x": true, "https://example.com:8443": true, `https://"><script>`: false,
	} {
		_, ok := httpLink(link)
		assert.Equal(t, want, ok, link)
	}
}

func TestAuthorHomepage(t *testing.T) {
	assert.Equal(t, "https://www.example.com", authorHomepage("www.example.com"))
	assert.Equal(t, "http://example.com", authorHomepage("http://example.com"))
	assert.Empty(t, authorHomepage("javascript:alert(1)"))
	assert.Empty(t, authorHomepage(`"><script>`))
	assert.Empty(t, authorHomepage(""))
}

func TestViewAnchor(t *testing.T) {
	assert.Equal(t, "asset-some-asset-1", viewAnchor("asset", "some-asset-1"))
	assert.Equal(t, "risk-a_40b_3ec_20_22_3c_5f", viewAnchor("risk", `a@b>c "<_`))
	assert.NotEqual(t, viewAnchor("risk", "a_40"), viewAnchor("risk", "a@"))
}

func TestHTMLContentSecurityPolicy(t *testing.T) {
	hash := sha256.Sum256([]byte(htmlReportCSS))
	assert.Equal(t, "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'; "+
		"base-uri 'none'; form-action 'none'", htmlContentSecurityPolicy(htmlReportCSS))
}
