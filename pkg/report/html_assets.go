package report

import (
	"html/template"
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

type htmlQuestion struct {
	Question string
	Answer   template.HTML
	Answered bool
}

type htmlTag struct {
	Tag  string
	Uses []htmlRef
}

type htmlRAAEntry struct {
	Asset       htmlRef
	RAA         string
	Severity    *htmlLevel
	Description template.HTML
}

type htmlOutOfScope struct {
	Asset         htmlRef
	Justification template.HTML
}

func (what *htmlReport) addModelChapters(parsedModel *types.Model) {
	for _, criticality := range types.CriticalityValues() {
		what.BusinessCriticality = append(what.BusinessCriticality, htmlChoice{
			Title: criticality.String(), Selected: criticality == parsedModel.BusinessCriticality,
		})
	}
	for _, title := range sortedKeysOfSecurityRequirements(parsedModel) {
		what.SecurityRequirements = append(what.SecurityRequirements,
			htmlTitledText{title, basicMarkup(parsedModel.SecurityRequirements[title])})
	}
	for _, title := range sortedKeysOfAbuseCases(parsedModel) {
		what.AbuseCases = append(what.AbuseCases, htmlTitledText{title, basicMarkup(parsedModel.AbuseCases[title])})
	}
	for _, question := range sortedKeysOfQuestions(parsedModel) {
		answer := strings.TrimSpace(parsedModel.Questions[question])
		what.Questions = append(what.Questions, htmlQuestion{question, basicMarkup(answer), answer != ""})
	}
	what.UnansweredQuestions = questionsUnanswered(parsedModel)
	what.Tags = htmlTags(parsedModel)

	for _, asset := range sortedTechnicalAssetsByRAAAndTitle(parsedModel) {
		if asset.OutOfScope {
			justification := asset.JustificationOutOfScope
			if justification == "" {
				justification = "Missing out of scope justification."
			}
			what.OutOfScope = append(what.OutOfScope,
				htmlOutOfScope{refTechnicalAsset(parsedModel, asset.Id), basicMarkup(justification)})
			continue
		}
		what.RAA = append(what.RAA, htmlRAAEntry{
			Asset:       refTechnicalAsset(parsedModel, asset.Id),
			RAA:         formatRAA(asset),
			Severity:    highestSeverityStillAtRisk(parsedModel.GeneratedRisks(asset)),
			Description: basicMarkup(asset.Description),
		})
	}
}

// htmlTags lists for each tag of the model what is tagged with it, as the PDF and AsciiDoc reports do.
func htmlTags(parsedModel *types.Model) []htmlTag {
	tagged := htmlTaggedObjects(parsedModel)
	tags := make([]htmlTag, 0)
	for _, tag := range slices.Sorted(slices.Values(parsedModel.TagsAvailable)) {
		uses := make([]htmlRef, 0)
		for _, object := range tagged {
			if contains(object.tags, tag) {
				uses = append(uses, object.ref)
			}
		}
		if len(uses) > 0 {
			tags = append(tags, htmlTag{tag, uses})
		}
	}
	return tags
}

type htmlTaggedObject struct {
	tags []string
	ref  htmlRef
}

// htmlTaggedObjects are the objects of the model that can have tags, in the order of the tag listing.
func htmlTaggedObjects(parsedModel *types.Model) []htmlTaggedObject {
	objects := make([]htmlTaggedObject, 0)
	for _, asset := range sortedTechnicalAssetsByTitle(parsedModel) {
		objects = append(objects, htmlTaggedObject{asset.Tags, refTechnicalAsset(parsedModel, asset.Id)})
		for _, link := range asset.CommunicationLinksSorted() {
			objects = append(objects, htmlTaggedObject{link.Tags, refCommunicationLink(link)})
		}
	}
	for _, asset := range sortedDataAssetsByTitle(parsedModel) {
		objects = append(objects, htmlTaggedObject{asset.Tags, refDataAsset(parsedModel, asset.Id)})
	}
	for _, boundary := range sortedTrustBoundariesByTitle(parsedModel) {
		objects = append(objects, htmlTaggedObject{boundary.Tags, refTrustBoundary(parsedModel, boundary.Id)})
	}
	for _, runtime := range sortedSharedRuntimesByTitle(parsedModel) {
		objects = append(objects, htmlTaggedObject{runtime.Tags, refSharedRuntime(parsedModel, runtime.Id)})
	}
	return objects
}

type htmlTechnicalAsset struct {
	Anchor          string
	Asset           *types.TechnicalAsset
	Severity        *htmlLevel
	Summary         string
	Description     template.HTML
	Justification   template.HTML
	RAA             string
	Tags            string
	FormatsAccepted string
	TrustBoundary   *htmlRef
	DataProcessed   []htmlRef
	DataStored      []htmlRef
	Outgoing        []htmlRef
	Incoming        []htmlRef
	Risks           []*htmlRisk
}

type htmlDataAsset struct {
	Anchor        string
	Asset         *types.DataAsset
	Summary       string
	Breach        *htmlLevel // the data breach probability still at risk, nil for none
	Description   template.HTML
	Justification template.HTML
	Tags          string
	ProcessedBy   []htmlRef
	StoredBy      []htmlRef
	SentVia       []htmlRef
	ReceivedVia   []htmlRef
	BreachRisks   []*htmlRisk
}

type htmlTrustBoundary struct {
	Anchor       string
	Boundary     *types.TrustBoundary
	Description  template.HTML
	Tags         string
	Parent       *htmlRef
	AssetsInside []htmlRef
	Nested       []htmlRef
}

type htmlSharedRuntime struct {
	Anchor        string
	Runtime       *types.SharedRuntime
	Description   template.HTML
	Tags          string
	AssetsRunning []htmlRef
}

type htmlCommunicationLink struct {
	Anchor       string
	Link         *types.CommunicationLink
	Description  template.HTML
	Tags         string
	Source       htmlRef
	Target       htmlRef
	Encrypted    bool
	DataSent     []htmlRef
	DataReceived []htmlRef
}

func (what *htmlReport) addAssetChapters(parsedModel *types.Model, risks htmlRisks) {
	for _, asset := range sortedTechnicalAssetsByRiskSeverityAndTitle(parsedModel) {
		what.TechnicalAssets = append(what.TechnicalAssets, newHTMLTechnicalAsset(parsedModel, asset, risks))
	}
	for _, asset := range sortedDataAssetsByDataBreachProbabilityAndTitle(parsedModel) {
		what.DataAssets = append(what.DataAssets, newHTMLDataAsset(parsedModel, asset, risks))
	}
	for _, boundary := range sortedTrustBoundariesByTitle(parsedModel) {
		view := htmlTrustBoundary{
			Anchor:       htmlAnchor("trust-boundary", boundary.Id),
			Boundary:     boundary,
			Description:  basicMarkup(boundary.Description),
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
		what.SharedRuntimes = append(what.SharedRuntimes, htmlSharedRuntime{
			Anchor:        htmlAnchor("shared-runtime", runtime.Id),
			Runtime:       runtime,
			Description:   basicMarkup(runtime.Description),
			Tags:          joinedOrNone(runtime.Tags),
			AssetsRunning: refsOfIDs(parsedModel, sortedCopy(runtime.TechnicalAssetsRunning), refTechnicalAsset),
		})
	}
	for _, asset := range sortedTechnicalAssetsByTitle(parsedModel) {
		for _, link := range asset.CommunicationLinksSorted() {
			what.CommunicationLinks = append(what.CommunicationLinks, newHTMLCommunicationLink(parsedModel, link))
		}
	}
}

func newHTMLTechnicalAsset(parsedModel *types.Model, asset *types.TechnicalAsset, risks htmlRisks) htmlTechnicalAsset {
	generatedRisks := parsedModel.GeneratedRisks(asset)
	view := htmlTechnicalAsset{
		Anchor:          htmlAnchor("asset", asset.Id),
		Asset:           asset,
		Severity:        highestSeverityStillAtRisk(generatedRisks),
		Summary:         riskSuffix(len(types.ReduceToOnlyStillAtRisk(generatedRisks)), len(generatedRisks)),
		Description:     basicMarkup(asset.Description),
		Justification:   basicMarkup(asset.JustificationCiaRating),
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
		view.Summary = "out of scope"
	}
	if boundary := parsedModel.GetTechnicalAssetTrustBoundaryId(asset); boundary != "" {
		ref := refTrustBoundary(parsedModel, boundary)
		view.TrustBoundary = &ref
	}
	return view
}

func newHTMLDataAsset(parsedModel *types.Model, asset *types.DataAsset, risks htmlRisks) htmlDataAsset {
	identifiedRisks := parsedModel.IdentifiedDataBreachProbabilityRisks(asset)
	breachRisks := identifiedDataBreachProbabilityRisksStillAtRisk(parsedModel, asset)
	sortByDataBreachProbability(breachRisks)
	view := htmlDataAsset{
		Anchor:        htmlAnchor("data-asset", asset.Id),
		Asset:         asset,
		Summary:       riskSuffix(len(types.ReduceToOnlyStillAtRisk(identifiedRisks)), len(identifiedRisks)),
		Description:   basicMarkup(asset.Description),
		Justification: basicMarkup(asset.JustificationCiaRating),
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
func dataBreachLevel(probability types.DataBreachProbability) htmlLevel {
	severity := types.LowSeverity
	switch probability {
	case types.Probable:
		severity = types.HighSeverity
	case types.Possible:
		severity = types.MediumSeverity
	case types.Improbable:
	}
	return htmlLevel{Title: probability.Title(), Class: severityLevel(severity).Class}
}

func newHTMLCommunicationLink(parsedModel *types.Model, link *types.CommunicationLink) htmlCommunicationLink {
	return htmlCommunicationLink{
		Anchor:       htmlAnchor("link", link.Id),
		Link:         link,
		Description:  basicMarkup(link.Description),
		Tags:         joinedOrNone(link.Tags),
		Source:       refTechnicalAsset(parsedModel, link.SourceId),
		Target:       refTechnicalAsset(parsedModel, link.TargetId),
		Encrypted:    link.Protocol.IsEncrypted(),
		DataSent:     refs(parsedModel.DataAssetsSentSorted(link), refDataAssetOf(parsedModel)),
		DataReceived: refs(parsedModel.DataAssetsReceivedSorted(link), refDataAssetOf(parsedModel)),
	}
}

func refDataAssetOf(parsedModel *types.Model) func(*types.DataAsset) htmlRef {
	return func(asset *types.DataAsset) htmlRef { return refDataAsset(parsedModel, asset.Id) }
}

func refTechnicalAssetOf(parsedModel *types.Model) func(*types.TechnicalAsset) htmlRef {
	return func(asset *types.TechnicalAsset) htmlRef { return refTechnicalAsset(parsedModel, asset.Id) }
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

// htmlNone stands for an empty list.
const htmlNone = "none"

func joinedOrNone(values []string) string {
	if len(values) == 0 {
		return htmlNone
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
