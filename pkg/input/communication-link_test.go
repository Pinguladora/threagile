package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommunicationLinkMergesVia covers the via list of a link defined in more than one file
// (threagile#15): the path through the proxies is one value, so an equal or missing list merges and a
// different one is a conflict rather than a union that would change the order.
func TestCommunicationLinkMergesVia(t *testing.T) {
	link := CommunicationLink{Target: "web-server"}
	require.NoError(t, link.Merge(CommunicationLink{Via: []string{"load-balancer", "waf"}}))
	assert.Equal(t, []string{"load-balancer", "waf"}, link.Via)

	require.NoError(t, link.Merge(CommunicationLink{Via: []string{"load-balancer", "waf"}}))
	require.NoError(t, link.Merge(CommunicationLink{}))
	assert.Equal(t, []string{"load-balancer", "waf"}, link.Via)

	err := link.Merge(CommunicationLink{Via: []string{"waf", "load-balancer"}})
	require.ErrorContains(t, err, "failed to merge via")
	assert.Equal(t, []string{"load-balancer", "waf"}, link.Via)
}
