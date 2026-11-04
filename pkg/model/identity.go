package model

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

// withLegacyIdentityMoved returns the communication link with the identity that earlier versions of the model put
// into its authorization (none, technical-user or end-user-identity-propagation) moved into its identity. Its
// authorization is then not modelled. A link with an identity is returned as it is.
func withLegacyIdentityMoved(commLink input.CommunicationLink) input.CommunicationLink {
	if commLink.Identity != "" {
		return commLink
	}
	if identity, ok := types.LegacyIdentity(commLink.Authorization); ok {
		commLink.Identity = identity.String()
		commLink.Authorization = ""
	}
	return commLink
}

// ConvertLegacyIdentities moves the identity that earlier versions of the model put into the authorization of the
// communication links into their identity, and returns how many links it converted.
func ConvertLegacyIdentities(modelInput *input.Model) int {
	converted := 0
	for _, assetTitle := range slices.Sorted(maps.Keys(modelInput.TechnicalAssets)) {
		technicalAsset := modelInput.TechnicalAssets[assetTitle]
		for _, linkTitle := range slices.Sorted(maps.Keys(technicalAsset.CommunicationLinks)) {
			link := technicalAsset.CommunicationLinks[linkTitle]
			moved := withLegacyIdentityMoved(link)
			if moved.Identity != link.Identity {
				technicalAsset.CommunicationLinks[linkTitle] = moved
				converted++
			}
		}
	}
	return converted
}

// parseLinkAccess parses the identity and the authorization of a communication link.
func parseLinkAccess(commLink input.CommunicationLink) (types.Identity, types.Authorization, error) {
	identity, err := types.ParseIdentity(commLink.Identity)
	if err != nil {
		return 0, 0, fmt.Errorf("unknown 'identity' value: %w", err)
	}
	authorization, err := types.ParseAuthorization(commLink.Authorization)
	if err != nil {
		if _, isIdentity := types.LegacyIdentity(commLink.Authorization); isIdentity {
			return 0, 0, fmt.Errorf("'authorization' value %q is an identity, move it into 'identity'",
				commLink.Authorization)
		}
		return 0, 0, fmt.Errorf("unknown 'authorization' value: %w", err)
	}
	return identity, authorization, nil
}
