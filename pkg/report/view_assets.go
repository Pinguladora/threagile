package report

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type viewQuestion struct {
	Question string
	Answer   markupText
	Answered bool
}

type viewTag struct {
	Tag  string
	Uses []viewRef
}

type viewRAAEntry struct {
	Asset       viewRef
	RAA         string
	Severity    *viewLevel
	Description markupText
}

type viewOutOfScope struct {
	Asset         viewRef
	Justification markupText
}

func (what *reportView) addModelChapters(parsedModel *types.Model) {
	for _, criticality := range types.CriticalityValues() {
		what.BusinessCriticality = append(what.BusinessCriticality, viewChoice{
			Title: criticality.String(), Selected: criticality == parsedModel.BusinessCriticality,
		})
	}
	for _, title := range sortedKeysOfSecurityRequirements(parsedModel) {
		what.SecurityRequirements = append(what.SecurityRequirements,
			viewTitledText{title, markupText(parsedModel.SecurityRequirements[title])})
	}
	for _, title := range sortedKeysOfAbuseCases(parsedModel) {
		what.AbuseCases = append(what.AbuseCases, viewTitledText{title, markupText(parsedModel.AbuseCases[title])})
	}
	for _, question := range sortedKeysOfQuestions(parsedModel) {
		answer := strings.TrimSpace(parsedModel.Questions[question])
		what.Questions = append(what.Questions, viewQuestion{question, markupText(answer), answer != ""})
	}
	what.UnansweredQuestions = questionsUnanswered(parsedModel)
	what.Tags = viewTags(parsedModel)

	for _, asset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if asset.OutOfScope {
			justification := asset.JustificationOutOfScope
			if justification == "" {
				justification = "Missing out of scope justification."
			}
			what.OutOfScope = append(what.OutOfScope,
				viewOutOfScope{refTechnicalAsset(parsedModel, asset.Id), markupText(justification)})
			continue
		}
		what.RAA = append(what.RAA, viewRAAEntry{
			Asset:       refTechnicalAsset(parsedModel, asset.Id),
			RAA:         formatRAA(asset),
			Severity:    highestSeverityStillAtRisk(parsedModel.GeneratedRisks(asset)),
			Description: markupText(asset.Description),
		})
	}
}

// viewTags lists for each tag of the model what is tagged with it, as the PDF and AsciiDoc reports do.
func viewTags(parsedModel *types.Model) []viewTag {
	tagged := viewTaggedObjects(parsedModel)
	tags := make([]viewTag, 0)
	for _, tag := range slices.Sorted(slices.Values(parsedModel.TagsAvailable)) {
		uses := make([]viewRef, 0)
		for _, object := range tagged {
			if contains(object.tags, tag) {
				uses = append(uses, object.ref)
			}
		}
		if len(uses) > 0 {
			tags = append(tags, viewTag{tag, uses})
		}
	}
	return tags
}

type viewTaggedObject struct {
	tags []string
	ref  viewRef
}

// viewTaggedObjects are the objects of the model that can have tags, in the order of the tag listing.
func viewTaggedObjects(parsedModel *types.Model) []viewTaggedObject {
	objects := make([]viewTaggedObject, 0)
	for _, asset := range sortedTechnicalAssetsByTitle(parsedModel) {
		objects = append(objects, viewTaggedObject{asset.Tags, refTechnicalAsset(parsedModel, asset.Id)})
		for _, link := range asset.CommunicationLinksSorted() {
			objects = append(objects, viewTaggedObject{link.Tags, refCommunicationLink(link)})
		}
	}
	for _, asset := range sortedDataAssetsByTitle(parsedModel) {
		objects = append(objects, viewTaggedObject{asset.Tags, refDataAsset(parsedModel, asset.Id)})
	}
	for _, boundary := range sortedTrustBoundariesByTitle(parsedModel) {
		objects = append(objects, viewTaggedObject{boundary.Tags, refTrustBoundary(parsedModel, boundary.Id)})
	}
	for _, runtime := range sortedSharedRuntimesByTitle(parsedModel) {
		objects = append(objects, viewTaggedObject{runtime.Tags, refSharedRuntime(parsedModel, runtime.Id)})
	}
	return objects
}

type viewTechnicalAsset struct {
	Anchor          string
	Asset           *types.TechnicalAsset
	Severity        *viewLevel
	Summary         string
	Description     markupText
	Justification   markupText
	OutOfScope      markupText // the justification of an asset out of scope
	RAA             string
	Tags            string
	FormatsAccepted string
	TrustBoundary   *viewRef
	DataProcessed   []viewRef
	DataStored      []viewRef
	Outgoing        []viewRef
	Incoming        []viewRef
	Risks           []*viewRisk
}

type viewDataAsset struct {
	Anchor        string
	Asset         *types.DataAsset
	Summary       string
	Breach        *viewLevel // the data breach probability still at risk, nil for none
	Description   markupText
	Justification markupText
	Tags          string
	ProcessedBy   []viewRef
	StoredBy      []viewRef
	SentVia       []viewRef
	ReceivedVia   []viewRef
	BreachRisks   []*viewRisk
}

type viewTrustBoundary struct {
	Anchor       string
	Boundary     *types.TrustBoundary
	Description  markupText
	Tags         string
	Parent       *viewRef
	AssetsInside []viewRef
	Nested       []viewRef
}

type viewSharedRuntime struct {
	Anchor        string
	Runtime       *types.SharedRuntime
	Description   markupText
	Tags          string
	AssetsRunning []viewRef
}

type viewCommunicationLink struct {
	Anchor       string
	Link         *types.CommunicationLink
	Description  markupText
	Tags         string
	Source       viewRef
	Target       viewRef
	Encrypted    bool
	DataSent     []viewRef
	DataReceived []viewRef
}

func (what *reportView) addAssetChapters(parsedModel *types.Model, risks viewRisks) {
	for _, asset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		what.TechnicalAssets = append(what.TechnicalAssets, newViewTechnicalAsset(parsedModel, asset, risks))
	}
	for _, asset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
		what.DataAssets = append(what.DataAssets, newViewDataAsset(parsedModel, asset, risks))
	}
	for _, boundary := range sortedTrustBoundariesByTitle(parsedModel) {
		view := viewTrustBoundary{
			Anchor:       viewAnchor("trust-boundary", boundary.Id),
			Boundary:     boundary,
			Description:  markupText(boundary.Description),
			Tags:         joinedOrNone(boundary.Tags),
			AssetsInside: refsOfIDs(parsedModel, sortedCopy(boundary.TechnicalAssetsInside), refTechnicalAsset),
			Nested:       refsOfIDs(parsedModel, sortedCopy(boundary.TrustBoundariesNested), refTrustBoundary),
		}
		if parent := parsedModel.FindParentTrustBoundary(boundary); parent != nil {
			ref := refTrustBoundary(parsedModel, parent.Id)
			view.Parent = &ref
		}
		what.TrustBoundaries = append(what.TrustBoundaries, view)
	}
	for _, runtime := range sortedSharedRuntimesByTitle(parsedModel) {
		what.SharedRuntimes = append(what.SharedRuntimes, viewSharedRuntime{
			Anchor:        viewAnchor("shared-runtime", runtime.Id),
			Runtime:       runtime,
			Description:   markupText(runtime.Description),
			Tags:          joinedOrNone(runtime.Tags),
			AssetsRunning: refsOfIDs(parsedModel, sortedCopy(runtime.TechnicalAssetsRunning), refTechnicalAsset),
		})
	}
	for _, asset := range sortedTechnicalAssetsByTitle(parsedModel) {
		for _, link := range asset.CommunicationLinksSorted() {
			what.CommunicationLinks = append(what.CommunicationLinks, newViewCommunicationLink(parsedModel, link))
		}
	}
}

func newViewTechnicalAsset(parsedModel *types.Model, asset *types.TechnicalAsset, risks viewRisks) viewTechnicalAsset {
	generatedRisks := parsedModel.GeneratedRisks(asset)
	view := viewTechnicalAsset{
		Anchor:          viewAnchor("asset", asset.Id),
		Asset:           asset,
		Severity:        highestSeverityStillAtRisk(generatedRisks),
		Summary:         riskSuffix(len(types.ReduceToOnlyStillAtRisk(generatedRisks)), len(generatedRisks)),
		Description:     markupText(asset.Description),
		Justification:   markupText(asset.JustificationCiaRating),
		OutOfScope:      markupText(asset.JustificationOutOfScope),
		RAA:             formatRAA(asset),
		Tags:            joinedOrNone(asset.Tags),
		FormatsAccepted: dataFormatTitles(asset.DataFormatsAcceptedSorted()),
		DataProcessed:   refs(parsedModel.DataAssetsProcessedSorted(asset), refDataAssetOf(parsedModel)),
		DataStored:      refs(parsedModel.DataAssetsStoredSorted(asset), refDataAssetOf(parsedModel)),
		Outgoing:        refs(asset.CommunicationLinksSorted(), refCommunicationLink),
		Incoming:        refs(incomingLinks(parsedModel, asset), refCommunicationLink),
		Risks:           risks.of(generatedRisks),
	}
	if asset.OutOfScope {
		view.Summary = viewOutOfScopeText
	}
	if boundary := parsedModel.GetTechnicalAssetTrustBoundaryId(asset); boundary != "" {
		ref := refTrustBoundary(parsedModel, boundary)
		view.TrustBoundary = &ref
	}
	return view
}

func newViewDataAsset(parsedModel *types.Model, asset *types.DataAsset, risks viewRisks) viewDataAsset {
	identifiedRisks := parsedModel.IdentifiedDataBreachProbabilityRisks(asset)
	breachRisks := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, asset)
	sortByDataBreachProbability(breachRisks)
	view := viewDataAsset{
		Anchor:        viewAnchor("data-asset", asset.Id),
		Asset:         asset,
		Summary:       riskSuffix(len(types.ReduceToOnlyStillAtRisk(identifiedRisks)), len(identifiedRisks)),
		Description:   markupText(asset.Description),
		Justification: markupText(asset.JustificationCiaRating),
		Tags:          joinedOrNone(asset.Tags),
		ProcessedBy:   refs(parsedModel.ProcessedByTechnicalAssetsSorted(asset), refTechnicalAssetOf(parsedModel)),
		StoredBy:      refs(parsedModel.StoredByTechnicalAssetsSorted(asset), refTechnicalAssetOf(parsedModel)),
		SentVia:       refs(parsedModel.SentViaCommLinksSorted(asset), refCommunicationLink),
		ReceivedVia:   refs(parsedModel.ReceivedViaCommLinksSorted(asset), refCommunicationLink),
		BreachRisks:   risks.of(breachRisks),
	}
	if isDataBreachPotentialStillAtRisk(parsedModel, asset) {
		level := dataBreachLevel(identifiedDataBreachProbabilityStillAtRisk(parsedModel, asset))
		view.Breach = &level
	}
	return view
}

// dataBreachLevel shows a data breach probability in the colours the diagrams give it.
func dataBreachLevel(probability types.DataBreachProbability) viewLevel {
	severity := types.LowSeverity
	switch probability {
	case types.Probable:
		severity = types.HighSeverity
	case types.Possible:
		severity = types.MediumSeverity
	case types.Improbable:
	}
	return viewLevel{Title: probability.Title(), Class: severityLevel(severity).Class}
}

func newViewCommunicationLink(parsedModel *types.Model, link *types.CommunicationLink) viewCommunicationLink {
	return viewCommunicationLink{
		Anchor:       viewAnchor("link", link.Id),
		Link:         link,
		Description:  markupText(link.Description),
		Tags:         joinedOrNone(link.Tags),
		Source:       refTechnicalAsset(parsedModel, link.SourceId),
		Target:       refTechnicalAsset(parsedModel, link.TargetId),
		Encrypted:    link.Protocol.IsEncrypted(),
		DataSent:     refs(parsedModel.DataAssetsSentSorted(link), refDataAssetOf(parsedModel)),
		DataReceived: refs(parsedModel.DataAssetsReceivedSorted(link), refDataAssetOf(parsedModel)),
	}
}

func refDataAssetOf(parsedModel *types.Model) func(*types.DataAsset) viewRef {
	return func(asset *types.DataAsset) viewRef { return refDataAsset(parsedModel, asset.Id) }
}

func refTechnicalAssetOf(parsedModel *types.Model) func(*types.TechnicalAsset) viewRef {
	return func(asset *types.TechnicalAsset) viewRef { return refTechnicalAsset(parsedModel, asset.Id) }
}

// incomingLinks are the communication links to an asset by title and id, as they come in the
// order of the model.
func incomingLinks(parsedModel *types.Model, asset *types.TechnicalAsset) []*types.CommunicationLink {
	links := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[asset.Id]
	return slices.SortedStableFunc(slices.Values(links), func(a, b *types.CommunicationLink) int {
		return strings.Compare(a.Title+"\x00"+a.Id, b.Title+"\x00"+b.Id)
	})
}

func sortedCopy(values []string) []string {
	return slices.Sorted(slices.Values(values))
}

// viewNone stands for an empty list.
const viewNone = "none"

func joinedOrNone(values []string) string {
	if len(values) == 0 {
		return viewNone
	}
	return strings.Join(sortedCopy(values), ", ")
}

func dataFormatTitles(formats []types.DataFormat) string {
	titles := make([]string, 0, len(formats))
	for _, format := range formats {
		titles = append(titles, format.Title())
	}
	return joinedOrNone(titles)
}
