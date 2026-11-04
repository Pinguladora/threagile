package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeEscapesHTMLLabelText(t *testing.T) {
	assert.Equal(t, `A &amp; B &lt;b&gt;x&lt;/b&gt; &quot;q&quot;`, encode(`A & B <b>x</b> "q"`))
}

func TestQuoteEscapesQuotedLabelText(t *testing.T) {
	assert.Equal(t, `say \"hi\" C:\\temp\nnext`, quote("say \"hi\" C:\\temp\r\nnext"))
}
