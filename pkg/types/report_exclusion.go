package types

import (
	"fmt"
	"slices"
	"strings"
)

// ReportExclusion is what the reports leave out of a model: technical assets by layer, tag, id or the trust boundary
// they are in. Whatever goes takes its links and risks along.
type ReportExclusion struct {
	Layers          []Layer  `json:"layers,omitempty"           yaml:"layers,omitempty"`
	Tags            []string `json:"tags,omitempty"             yaml:"tags,omitempty"`
	TechnicalAssets []string `json:"technical_assets,omitempty" yaml:"technical_assets,omitempty"`
	TrustBoundaries []string `json:"trust_boundaries,omitempty" yaml:"trust_boundaries,omitempty"`
}

// The prefixes of the selectors of ParseReportExclusion.
const (
	layerSelector          = "layer:"
	tagSelector            = "tag:"
	technicalAssetSelector = "asset:"
	trustBoundarySelector  = "boundary:"
)

// IsEmpty reports whether the exclusion leaves nothing out.
func (what ReportExclusion) IsEmpty() bool {
	return len(what.Layers) == 0 && len(what.Tags) == 0 && len(what.TechnicalAssets) == 0 &&
		len(what.TrustBoundaries) == 0
}

// ParseReportExclusion parses selectors like layer:delivery, tag:ci, asset:renovate or boundary:github, as the
// --report-exclude flag takes them. Empty selectors are skipped.
func ParseReportExclusion(selectors []string) (ReportExclusion, error) {
	var result ReportExclusion
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		switch {
		case selector == "":
		case strings.HasPrefix(selector, layerSelector):
			layer, err := ParseLayer(strings.TrimPrefix(selector, layerSelector))
			if err != nil || layer == UnsetLayer {
				return result, fmt.Errorf("unknown layer in %q, use application, platform or delivery", selector)
			}
			result.Layers = append(result.Layers, layer)
		case strings.HasPrefix(selector, tagSelector):
			result.Tags = append(result.Tags, strings.ToLower(strings.TrimPrefix(selector, tagSelector)))
		case strings.HasPrefix(selector, technicalAssetSelector):
			result.TechnicalAssets = append(result.TechnicalAssets, strings.TrimPrefix(selector, technicalAssetSelector))
		case strings.HasPrefix(selector, trustBoundarySelector):
			result.TrustBoundaries = append(result.TrustBoundaries, strings.TrimPrefix(selector, trustBoundarySelector))
		default:
			return result, fmt.Errorf("unknown report exclusion %q, use layer:, tag:, asset: or boundary: and a name",
				selector)
		}
	}
	return result, nil
}

// String describes the exclusion, like "layer delivery, tag ci and trust boundary github".
func (what ReportExclusion) String() string {
	parts := make([]string, 0,
		len(what.Layers)+len(what.Tags)+len(what.TechnicalAssets)+len(what.TrustBoundaries))
	for _, layer := range what.Layers {
		parts = append(parts, "layer "+layer.String())
	}
	for _, tag := range what.Tags {
		parts = append(parts, "tag "+tag)
	}
	for _, id := range what.TechnicalAssets {
		parts = append(parts, "technical asset "+id)
	}
	for _, id := range what.TrustBoundaries {
		parts = append(parts, "trust boundary "+id)
	}
	last := len(parts) - 1
	if last <= 0 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:last], ", ") + " and " + parts[last]
}

// CheckReportExclusion returns an error for a tag, technical asset or trust boundary of the exclusion that the model
// does not have, so that a typo does not silently leave nothing out.
func (model *Model) CheckReportExclusion(exclusion ReportExclusion) error {
	for _, tag := range exclusion.Tags {
		if !slices.Contains(model.TagsAvailable, tag) {
			return fmt.Errorf("report exclusion names the tag %q, which is not in tags_available", tag)
		}
	}
	for _, id := range exclusion.TechnicalAssets {
		if model.TechnicalAssets[id] == nil {
			return fmt.Errorf("report exclusion names the technical asset %q, which the model does not have", id)
		}
	}
	for _, id := range exclusion.TrustBoundaries {
		if model.TrustBoundaries[id] == nil {
			return fmt.Errorf("report exclusion names the trust boundary %q, which the model does not have", id)
		}
	}
	return nil
}

// excludedTechnicalAssets returns the ids of the technical assets the exclusion covers.
func (model *Model) excludedTechnicalAssets(exclusion ReportExclusion) map[string]bool {
	excluded := make(map[string]bool)
	for id, asset := range model.TechnicalAssets {
		if slices.Contains(exclusion.Layers, asset.ReportLayer()) || asset.IsTaggedWithAny(exclusion.Tags...) ||
			slices.Contains(exclusion.TechnicalAssets, id) {
			excluded[id] = true
		}
	}
	for _, boundaryId := range exclusion.TrustBoundaries {
		if boundary := model.TrustBoundaries[boundaryId]; boundary != nil {
			for _, id := range model.RecursivelyAllTechnicalAssetIDsInside(boundary) {
				excluded[id] = true
			}
		}
	}
	return excluded
}
