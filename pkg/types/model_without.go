package types

import (
	"maps"
	"slices"
)

// LeftOut is what a report leaves out of the model: the exclusion, and how many technical assets and risks it took.
type LeftOut struct {
	Exclusion       ReportExclusion
	TechnicalAssets int
	Risks           int
}

// Without returns a copy of the model for the reports without the technical assets the exclusion covers, the links
// from and to them, and the risks about them. Data assets that only those assets held go too, and so do trust
// boundaries and shared runtimes they leave empty. The model itself is not changed: the analysis and its JSON outputs
// keep everything. With an empty exclusion, it returns the model itself and no LeftOut.
func (model *Model) Without(exclusion ReportExclusion) (*Model, *LeftOut) {
	if exclusion.IsEmpty() {
		return model, nil
	}
	leftOut := &LeftOut{Exclusion: exclusion}
	result := *model

	result.TechnicalAssets, leftOut.TechnicalAssets = keptTechnicalAssets(model.TechnicalAssets,
		model.excludedTechnicalAssets(exclusion))
	kept := func(id string) bool { return result.TechnicalAssets[id] != nil }
	result.keepLinks(model)
	result.DataAssets = keptDataAssets(model, &result)
	result.TrustBoundaries, result.DirectContainingTrustBoundaryMappedByTechnicalAssetId = keptTrustBoundaries(model, kept)
	result.SharedRuntimes = keptSharedRuntimes(model.SharedRuntimes, kept)
	leftOut.Risks = result.keepRisks(model)
	return &result, leftOut
}

// keptTechnicalAssets returns copies of the technical assets that are not excluded, and how many it left out.
func keptTechnicalAssets(technicalAssets map[string]*TechnicalAsset, excluded map[string]bool,
) (map[string]*TechnicalAsset, int) {
	kept := make(map[string]*TechnicalAsset, len(technicalAssets))
	for id, asset := range technicalAssets {
		if !excluded[id] {
			copied := *asset
			kept[id] = &copied
		}
	}
	return kept, len(technicalAssets) - len(kept)
}

// keepLinks keeps the links of the original model between technical assets that this model still has.
func (model *Model) keepLinks(original *Model) {
	model.CommunicationLinks = make(map[string]*CommunicationLink, len(original.CommunicationLinks))
	for id, link := range original.CommunicationLinks {
		if model.TechnicalAssets[link.SourceId] != nil && model.TechnicalAssets[link.TargetId] != nil {
			model.CommunicationLinks[id] = link
		}
	}
	gone := func(link *CommunicationLink) bool { return model.CommunicationLinks[link.Id] == nil }
	for _, asset := range model.TechnicalAssets {
		asset.CommunicationLinks = slices.DeleteFunc(slices.Clone(asset.CommunicationLinks), gone)
	}
	model.IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]*CommunicationLink)
	for target, links := range original.IncomingTechnicalCommunicationLinksMappedByTargetId {
		if links = slices.DeleteFunc(slices.Clone(links), gone); len(links) > 0 {
			model.IncomingTechnicalCommunicationLinksMappedByTargetId[target] = links
		}
	}
}

// keepRisks keeps copies of the risks of the original model that this model can still show, and returns how many it
// left out. The technical assets a risk may breach data of are limited to those that are kept.
func (model *Model) keepRisks(original *Model) int {
	leftOut := 0
	model.GeneratedRisksByCategory = make(map[string][]*Risk, len(original.GeneratedRisksByCategory))
	model.GeneratedRisksBySyntheticId = make(map[string]*Risk, len(original.GeneratedRisksBySyntheticId))
	for category, risks := range original.GeneratedRisksByCategory {
		kept := make([]*Risk, 0, len(risks))
		for _, risk := range risks {
			if !model.keepsRisk(risk) {
				leftOut++
				continue
			}
			copied := *risk
			copied.DataBreachTechnicalAssetIDs = slices.DeleteFunc(slices.Clone(risk.DataBreachTechnicalAssetIDs),
				func(id string) bool { return model.TechnicalAssets[id] == nil })
			kept = append(kept, &copied)
			model.GeneratedRisksBySyntheticId[copied.SyntheticId] = &copied
		}
		if len(kept) > 0 {
			model.GeneratedRisksByCategory[category] = kept
		}
	}
	return leftOut
}

// keepsRisk reports whether every model element the risk is about is still in the model.
func (model *Model) keepsRisk(risk *Risk) bool {
	for _, element := range []struct {
		id   string
		kept bool
	}{
		{risk.MostRelevantTechnicalAssetId, model.TechnicalAssets[risk.MostRelevantTechnicalAssetId] != nil},
		{risk.MostRelevantCommunicationLinkId, model.CommunicationLinks[risk.MostRelevantCommunicationLinkId] != nil},
		{risk.MostRelevantDataAssetId, model.DataAssets[risk.MostRelevantDataAssetId] != nil},
		{risk.MostRelevantTrustBoundaryId, model.TrustBoundaries[risk.MostRelevantTrustBoundaryId] != nil},
		{risk.MostRelevantSharedRuntimeId, model.SharedRuntimes[risk.MostRelevantSharedRuntimeId] != nil},
	} {
		if element.id != "" && !element.kept {
			return false
		}
	}
	return true
}

// keptDataAssets returns the data assets of the original model without those that only left out technical assets or
// their links held. A data asset that nothing held to begin with stays.
func keptDataAssets(original *Model, result *Model) map[string]*DataAsset {
	heldBefore, heldNow := heldDataAssets(original), heldDataAssets(result)
	kept := make(map[string]*DataAsset, len(original.DataAssets))
	for id, dataAsset := range original.DataAssets {
		if heldNow[id] || !heldBefore[id] {
			kept[id] = dataAsset
		}
	}
	return kept
}

// heldDataAssets returns the ids of the data assets that the technical assets of the model or their links hold.
func heldDataAssets(model *Model) map[string]bool {
	held := make(map[string]bool)
	for _, asset := range model.TechnicalAssets {
		for _, id := range slices.Concat(asset.DataAssetsProcessed, asset.DataAssetsStored) {
			held[id] = true
		}
		for _, link := range asset.CommunicationLinks {
			for _, id := range slices.Concat(link.DataAssetsSent, link.DataAssetsReceived) {
				held[id] = true
			}
		}
	}
	return held
}

// keptSharedRuntimes returns copies of the shared runtimes with the kept technical assets only, without those left
// empty. One that was empty to begin with stays.
func keptSharedRuntimes(runtimes map[string]*SharedRuntime, kept func(id string) bool) map[string]*SharedRuntime {
	result := make(map[string]*SharedRuntime, len(runtimes))
	for id, runtime := range runtimes {
		copied := *runtime
		copied.TechnicalAssetsRunning = slices.DeleteFunc(slices.Clone(runtime.TechnicalAssetsRunning),
			func(id string) bool { return !kept(id) })
		if len(copied.TechnicalAssetsRunning) > 0 || len(runtime.TechnicalAssetsRunning) == 0 {
			result[id] = &copied
		}
	}
	return result
}

// keptTrustBoundaries returns copies of the trust boundaries with the kept technical assets only, without those left
// with neither assets nor nested boundaries, and the boundary that directly holds each kept asset.
func keptTrustBoundaries(model *Model, kept func(id string) bool,
) (map[string]*TrustBoundary, map[string]*TrustBoundary) {
	boundaries := make(map[string]*TrustBoundary, len(model.TrustBoundaries))
	for id, boundary := range model.TrustBoundaries {
		copied := *boundary
		copied.TechnicalAssetsInside = slices.DeleteFunc(slices.Clone(boundary.TechnicalAssetsInside),
			func(id string) bool { return !kept(id) })
		copied.TrustBoundariesNested = slices.Clone(boundary.TrustBoundariesNested)
		boundaries[id] = &copied
	}
	// Leaving out an empty boundary can empty the boundary around it, so repeat until nothing changes.
	for pruneEmptyBoundaries(boundaries, model.TrustBoundaries) {
	}

	containing := make(map[string]*TrustBoundary, len(model.DirectContainingTrustBoundaryMappedByTechnicalAssetId))
	for assetId, boundary := range model.DirectContainingTrustBoundaryMappedByTechnicalAssetId {
		if kept(assetId) && boundaries[boundary.Id] != nil {
			containing[assetId] = boundaries[boundary.Id]
		}
	}
	return boundaries, containing
}

// pruneEmptyBoundaries removes the boundaries that hold neither assets nor nested boundaries any more, and the
// references to removed ones. A boundary that was empty to begin with stays. It reports whether it removed any.
func pruneEmptyBoundaries(boundaries map[string]*TrustBoundary, original map[string]*TrustBoundary) bool {
	empty := func(boundary *TrustBoundary) bool {
		return len(boundary.TechnicalAssetsInside) == 0 && len(boundary.TrustBoundariesNested) == 0
	}
	removed := false
	for _, id := range slices.Sorted(maps.Keys(boundaries)) {
		boundary := boundaries[id]
		boundary.TrustBoundariesNested = slices.DeleteFunc(boundary.TrustBoundariesNested,
			func(nested string) bool { return boundaries[nested] == nil })
		if empty(boundary) && !empty(original[id]) {
			delete(boundaries, id)
			removed = true
		}
	}
	return removed
}
