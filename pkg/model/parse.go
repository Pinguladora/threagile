package model

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

type technologyMapConfigReader interface {
	GetAppFolder() string
	GetTechnologyFilename() string
}

func ParseModel(
	config technologyMapConfigReader, modelInput *input.Model,
	builtinRiskRules types.RiskRules, customRiskRules types.RiskRules,
) (*types.Model, error) {
	technologies, err := loadTechnologies(config)
	if err != nil {
		return nil, err
	}

	parsedModel, err := newParsedModel(modelInput)
	if err != nil {
		return nil, err
	}

	err = parseDataAssets(parsedModel, modelInput)
	if err != nil {
		return nil, err
	}

	err = parseTechnicalAssets(parsedModel, modelInput, technologies)
	if err != nil {
		return nil, err
	}

	err = parseTrustBoundaries(parsedModel, modelInput)
	if err != nil {
		return nil, err
	}

	err = parseSharedRuntimes(parsedModel, modelInput)
	if err != nil {
		return nil, err
	}

	addRiskRuleCategories(parsedModel, builtinRiskRules, customRiskRules)

	err = parseCustomRiskCategories(parsedModel, modelInput)
	if err != nil {
		return nil, err
	}

	err = parseRiskTracking(parsedModel, modelInput)
	if err != nil {
		return nil, err
	}

	err = checkCommunicationLinkTargets(parsedModel)
	if err != nil {
		return nil, err
	}

	// to debug the parsing, write modelInput and parsedModel out here as YAML and JSON

	return parsedModel, nil
}

func loadTechnologies(config technologyMapConfigReader) (types.TechnologyMap, error) {
	technologies := make(types.TechnologyMap)
	technologiesLoadError := technologies.LoadWithConfig(config, "technologies.yaml")
	if technologiesLoadError != nil {
		return nil, fmt.Errorf("error loading technologies: %w", technologiesLoadError)
	}

	technologies.PropagateAttributes()
	return technologies, nil
}

// newParsedModel starts the parsed model with the overall attributes of the model and empty indexes.
func newParsedModel(modelInput *input.Model) (*types.Model, error) {
	businessCriticality, err := types.ParseCriticality(modelInput.BusinessCriticality)
	if err != nil {
		return nil, fmt.Errorf("unknown 'business_criticality' value of application: %v", modelInput.BusinessCriticality)
	}

	reportDate := types.Now()
	if len(modelInput.Date) > 0 {
		var parseError error
		reportDate, parseError = time.Parse("2006-01-02", modelInput.Date)
		if parseError != nil {
			return nil, errors.New("unable to parse 'date' value of model file (expected format: '2006-01-02')")
		}
	}

	parsedModel := &types.Model{
		ThreagileVersion:               modelInput.ThreagileVersion,
		Title:                          modelInput.Title,
		Author:                         convertAuthor(modelInput.Author),
		Contributors:                   convertAuthors(modelInput.Contributors),
		Date:                           types.Date{Time: reportDate},
		AppDescription:                 removePathElementsFromImageFiles(modelInput.AppDescription),
		BusinessOverview:               removePathElementsFromImageFiles(modelInput.BusinessOverview),
		TechnicalOverview:              removePathElementsFromImageFiles(modelInput.TechnicalOverview),
		BusinessCriticality:            businessCriticality,
		ManagementSummaryComment:       modelInput.ManagementSummaryComment,
		SecurityRequirements:           modelInput.SecurityRequirements,
		Questions:                      modelInput.Questions,
		AbuseCases:                     modelInput.AbuseCases,
		TagsAvailable:                  lowerCaseAndTrim(modelInput.TagsAvailable),
		DiagramTweakNodesep:            modelInput.DiagramTweakNodesep,
		DiagramTweakRanksep:            modelInput.DiagramTweakRanksep,
		DiagramTweakEdgeLayout:         modelInput.DiagramTweakEdgeLayout,
		DiagramTweakSuppressEdgeLabels: modelInput.DiagramTweakSuppressEdgeLabels,
		DiagramTweakLayoutLeftToRight:  modelInput.DiagramTweakLayoutLeftToRight,
		DiagramTweakInvisibleConnectionsBetweenAssets: modelInput.DiagramTweakInvisibleConnectionsBetweenAssets,
		DiagramTweakSameRankAssets:                    modelInput.DiagramTweakSameRankAssets,
	}

	parsedModel.CommunicationLinks = make(map[string]*types.CommunicationLink)
	parsedModel.AllSupportedTags = make(map[string]bool)
	parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId = make(map[string][]*types.CommunicationLink)
	parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId = make(map[string]*types.TrustBoundary)
	parsedModel.GeneratedRisksByCategory = make(map[string][]*types.Risk)
	parsedModel.GeneratedRisksBySyntheticId = make(map[string]*types.Risk)

	if parsedModel.DiagramTweakNodesep == 0 {
		parsedModel.DiagramTweakNodesep = 2
	}
	if parsedModel.DiagramTweakRanksep == 0 {
		parsedModel.DiagramTweakRanksep = 2
	}

	return parsedModel, nil
}

// ciaRating is the confidentiality, integrity and availability rating of an asset.
type ciaRating struct {
	confidentiality types.Confidentiality
	integrity       types.Criticality
	availability    types.Criticality
}

// parseCIA parses the confidentiality, integrity and availability of the asset that where names.
func parseCIA(confidentiality, integrity, availability string, where string) (ciaRating, error) {
	var rating ciaRating
	var err error
	rating.confidentiality, err = types.ParseConfidentiality(confidentiality)
	if err != nil {
		return rating, fmt.Errorf("unknown 'confidentiality' value of %v: %v", where, confidentiality)
	}
	rating.integrity, err = types.ParseCriticality(integrity)
	if err != nil {
		return rating, fmt.Errorf("unknown 'integrity' value of %v: %v", where, integrity)
	}
	rating.availability, err = types.ParseCriticality(availability)
	if err != nil {
		return rating, fmt.Errorf("unknown 'availability' value of %v: %v", where, availability)
	}
	return rating, nil
}

// Data Assets ===============================================================================

func parseDataAssets(parsedModel *types.Model, modelInput *input.Model) error {
	parsedModel.DataAssets = make(map[string]*types.DataAsset)
	for _, title := range slices.Sorted(maps.Keys(modelInput.DataAssets)) {
		dataAsset, err := parseDataAsset(parsedModel, title, modelInput.DataAssets[title])
		if err != nil {
			return err
		}
		parsedModel.DataAssets[dataAsset.Id] = dataAsset
	}
	return nil
}

func parseDataAsset(parsedModel *types.Model, title string, asset input.DataAsset) (*types.DataAsset, error) {
	id := asset.ID

	usage, err := types.ParseUsage(asset.Usage)
	if err != nil {
		return nil, fmt.Errorf("unknown 'usage' value of data asset %q: %v", title, asset.Usage)
	}
	quantity, err := types.ParseQuantity(asset.Quantity)
	if err != nil {
		return nil, fmt.Errorf("unknown 'quantity' value of data asset %q: %v", title, asset.Quantity)
	}
	cia, err := parseCIA(asset.Confidentiality, asset.Integrity, asset.Availability,
		fmt.Sprintf("data asset %q", title))
	if err != nil {
		return nil, err
	}

	err = checkIdSyntax(id)
	if err != nil {
		return nil, err
	}
	if _, exists := parsedModel.DataAssets[id]; exists {
		return nil, fmt.Errorf("duplicate id used: %v", id)
	}
	tags, err := parsedModel.CheckTags(lowerCaseAndTrim(asset.Tags), "data asset '"+title+"'")
	if err != nil {
		return nil, err
	}
	return &types.DataAsset{
		Id:                     id,
		Title:                  title,
		Usage:                  usage,
		Description:            withDefault(asset.Description, title),
		Quantity:               quantity,
		Tags:                   tags,
		Origin:                 asset.Origin,
		Owner:                  asset.Owner,
		Confidentiality:        cia.confidentiality,
		Integrity:              cia.integrity,
		Availability:           cia.availability,
		JustificationCiaRating: asset.JustificationCiaRating,
	}, nil
}

// Technical Assets ===============================================================================

// technicalAssetParser carries what parsing the technical assets one after the other builds up.
type technicalAssetParser struct {
	parsedModel  *types.Model
	technologies types.TechnologyMap
	// the via lists of communication links refer to technical assets that may be parsed later
	technicalAssetIds map[string]bool
	// hops of communication links through proxies, which the proxies own once they are parsed
	proxyHops []*types.CommunicationLink
	hopOwners map[string]bool
}

func parseTechnicalAssets(parsedModel *types.Model, modelInput *input.Model, technologies types.TechnologyMap) error {
	parsedModel.TechnicalAssets = make(map[string]*types.TechnicalAsset)
	parser := &technicalAssetParser{
		parsedModel:       parsedModel,
		technologies:      technologies,
		technicalAssetIds: make(map[string]bool, len(modelInput.TechnicalAssets)),
		proxyHops:         make([]*types.CommunicationLink, 0),
		hopOwners:         make(map[string]bool),
	}
	for _, asset := range modelInput.TechnicalAssets {
		parser.technicalAssetIds[asset.ID] = true
	}
	for _, title := range slices.Sorted(maps.Keys(modelInput.TechnicalAssets)) {
		technicalAsset, err := parser.parseTechnicalAsset(title, modelInput.TechnicalAssets[title])
		if err != nil {
			return err
		}
		parsedModel.TechnicalAssets[technicalAsset.Id] = technicalAsset
	}

	parser.addProxyHops()
	raiseTechnicalAssetCIA(parsedModel)
	return addDataAssetsProcessedByTargets(parsedModel)
}

func (parser *technicalAssetParser) parseTechnicalAsset(
	title string, asset input.TechnicalAsset,
) (*types.TechnicalAsset, error) {
	technicalAsset := &types.TechnicalAsset{
		Id:                      asset.ID,
		Title:                   title, // fmt.Sprintf("%v", asset["title"]),
		Description:             withDefault(asset.Description, title),
		Internet:                asset.Internet,
		MultiTenant:             asset.MultiTenant,
		Redundant:               asset.Redundant,
		Privileged:              asset.Privileged,
		CustomDevelopedParts:    asset.CustomDevelopedParts,
		UsedAsClientByHuman:     asset.UsedAsClientByHuman,
		OutOfScope:              asset.OutOfScope,
		JustificationOutOfScope: asset.JustificationOutOfScope,
		Owner:                   asset.Owner,
		JustificationCiaRating:  asset.JustificationCiaRating,
		DiagramTweakOrder:       asset.DiagramTweakOrder,
	}

	var err error
	technicalAsset.Usage, err = types.ParseUsage(asset.Usage)
	if err != nil {
		return nil, fmt.Errorf("unknown 'usage' value of technical asset %q: %v", title, asset.Usage)
	}

	technicalAsset.DataAssetsStored, err = appendCheckedDataAssets(parser.parsedModel, make([]string, 0),
		asset.DataAssetsStored, fmt.Sprintf("technical asset %q", title))
	if err != nil {
		return nil, err
	}

	technicalAsset.DataAssetsProcessed, err = appendCheckedDataAssets(parser.parsedModel, technicalAsset.DataAssetsStored,
		asset.DataAssetsProcessed, "technical asset '"+title+"'")
	if err != nil {
		return nil, err
	}

	err = parser.parseTechnicalAssetAttributes(technicalAsset, title, asset)
	if err != nil {
		return nil, err
	}

	err = parser.parseCommunicationLinks(technicalAsset, title, asset)
	if err != nil {
		return nil, err
	}

	err = checkIdSyntax(technicalAsset.Id)
	if err != nil {
		return nil, err
	}
	if _, exists := parser.parsedModel.TechnicalAssets[technicalAsset.Id]; exists {
		return nil, fmt.Errorf("duplicate id used: %v", technicalAsset.Id)
	}
	technicalAsset.Tags, err = parser.parsedModel.CheckTags(lowerCaseAndTrim(asset.Tags),
		fmt.Sprintf("technical asset %q", title))
	if err != nil {
		return nil, err
	}
	return technicalAsset, nil
}

// appendCheckedDataAssets appends the referenced data assets that the list does not have yet, after
// checking that they exist.
func appendCheckedDataAssets(
	parsedModel *types.Model, list []string, references []string, where string,
) ([]string, error) {
	for _, referencedAsset := range references {
		if contains(list, referencedAsset) {
			continue
		}

		err := parsedModel.CheckDataAssetTargetExists(referencedAsset, where)
		if err != nil {
			return nil, err
		}
		list = append(list, referencedAsset)
	}
	return list, nil
}

// parseTechnicalAssetAttributes parses the type, size, technologies, encryption, machine, CIA rating and
// accepted data formats of a technical asset.
func (parser *technicalAssetParser) parseTechnicalAssetAttributes(
	technicalAsset *types.TechnicalAsset, title string, asset input.TechnicalAsset,
) error {
	var err error
	technicalAsset.Type, err = types.ParseTechnicalAssetType(asset.Type)
	if err != nil {
		return fmt.Errorf("unknown 'type' value of technical asset %q: %v", title, asset.Type)
	}
	technicalAsset.Size, err = types.ParseTechnicalAssetSize(asset.Size)
	if err != nil {
		return fmt.Errorf("unknown 'size' value of technical asset %q: %v", title, asset.Size)
	}

	technicalAsset.Technologies, err = parser.parseTechnologies(title, asset)
	if err != nil {
		return err
	}

	technicalAsset.Encryption, err = types.ParseEncryptionStyle(asset.Encryption)
	if err != nil {
		return fmt.Errorf("unknown 'encryption' value of technical asset %q: %v", title, asset.Encryption)
	}
	technicalAsset.Machine, err = types.ParseTechnicalAssetMachine(asset.Machine)
	if err != nil {
		return fmt.Errorf("unknown 'machine' value of technical asset %q: %v", title, asset.Machine)
	}
	cia, err := parseCIA(asset.Confidentiality, asset.Integrity, asset.Availability,
		fmt.Sprintf("technical asset %q", title))
	if err != nil {
		return err
	}
	technicalAsset.Confidentiality = cia.confidentiality
	technicalAsset.Integrity = cia.integrity
	technicalAsset.Availability = cia.availability

	technicalAsset.DataFormatsAccepted, err = parseDataFormats(title, asset.DataFormatsAccepted)
	return err
}

func (parser *technicalAssetParser) parseTechnologies(
	title string, asset input.TechnicalAsset,
) ([]*types.Technology, error) {
	technicalAssetTechnologies := make([]*types.Technology, 0)

	allTechnologies := asset.Technologies
	if asset.Technology != "" {
		allTechnologies = append(allTechnologies, asset.Technology)
	}
	for _, technologyName := range allTechnologies {
		technicalAssetTechnology := parser.technologies.Get(technologyName)
		if technicalAssetTechnology == nil {
			return nil, fmt.Errorf("unknown 'technology' value of technical asset %q: %v", title, asset.Technology)
		}

		technicalAssetTechnologies = append(technicalAssetTechnologies, technicalAssetTechnology)
	}
	return technicalAssetTechnologies, nil
}

func parseDataFormats(title string, dataFormatNames []string) ([]types.DataFormat, error) {
	dataFormatsAccepted := make([]types.DataFormat, 0)
	for _, dataFormatName := range dataFormatNames {
		dataFormat, err := types.ParseDataFormat(dataFormatName)
		if err != nil {
			return nil, fmt.Errorf("unknown 'data_formats_accepted' value of technical asset %q: %v", title, dataFormatName)
		}
		dataFormatsAccepted = append(dataFormatsAccepted, dataFormat)
	}
	return dataFormatsAccepted, nil
}

// parseCommunicationLinks parses the outgoing communication links of a technical asset, which processes
// the data assets that its links send or receive.
func (parser *technicalAssetParser) parseCommunicationLinks(
	technicalAsset *types.TechnicalAsset, title string, asset input.TechnicalAsset,
) error {
	technicalAsset.CommunicationLinks = make([]*types.CommunicationLink, 0)
	for _, commLinkTitle := range slices.Sorted(maps.Keys(asset.CommunicationLinks)) {
		commLink := asset.CommunicationLinks[commLinkTitle]
		link, err := parser.parseCommunicationLink(technicalAsset, title, commLinkTitle, commLink)
		if err != nil {
			return err
		}
		if len(commLink.Via) > 0 {
			where := fmt.Sprintf("communication link %q of technical asset %q", commLinkTitle, title)
			hops, err := expandVia(link, commLink.Via, parser.technicalAssetIds, where)
			if err != nil {
				return err
			}
			link = hops[0]
			parser.proxyHops = append(parser.proxyHops, hops[1:]...)
			parser.hopOwners[technicalAsset.Id] = true
		}
		technicalAsset.CommunicationLinks = append(technicalAsset.CommunicationLinks, link)
		addCommunicationLink(parser.parsedModel, link)
	}
	return nil
}

func (parser *technicalAssetParser) parseCommunicationLink(
	technicalAsset *types.TechnicalAsset, title string, commLinkTitle string, commLink input.CommunicationLink,
) (*types.CommunicationLink, error) {
	link, err := newCommunicationLink(technicalAsset.Id, title, commLinkTitle, commLink)
	if err != nil {
		return nil, err
	}

	link.DataAssetsSent, technicalAsset.DataAssetsProcessed, err = appendLinkDataAssets(parser.parsedModel, nil,
		technicalAsset.DataAssetsProcessed, commLink.DataAssetsSent,
		fmt.Sprintf("communication link %q of technical asset %q", commLinkTitle, title))
	if err != nil {
		return nil, err
	}

	link.DataAssetsReceived, technicalAsset.DataAssetsProcessed, err = appendLinkDataAssets(parser.parsedModel, nil,
		technicalAsset.DataAssetsProcessed, commLink.DataAssetsReceived,
		"communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
	if err != nil {
		return nil, err
	}

	if commLink.DiagramTweakWeight > 0 {
		link.DiagramTweakWeight = commLink.DiagramTweakWeight
	}

	link.Id = createDataFlowId(technicalAsset.Id, commLinkTitle)
	link.Tags, err = parser.parsedModel.CheckTags(lowerCaseAndTrim(commLink.Tags),
		"communication link '"+commLinkTitle+"' of technical asset '"+title+"'")
	if err != nil {
		return nil, err
	}
	return link, nil
}

// newCommunicationLink starts a communication link of the source asset with its parsed protocol,
// authentication, identity, authorization and usage.
func newCommunicationLink(
	sourceId string, title string, commLinkTitle string, commLink input.CommunicationLink,
) (*types.CommunicationLink, error) {
	authentication, err := types.ParseAuthentication(commLink.Authentication)
	if err != nil {
		return nil, fmt.Errorf("unknown 'authentication' value of technical asset %q communication link %q: %v",
			title, commLinkTitle, commLink.Authentication)
	}
	identity, authorization, err := parseLinkAccess(withLegacyIdentityMoved(commLink))
	if err == nil {
		err = checkLinkAccount(identity, commLink.Account)
	}
	if err != nil {
		return nil, fmt.Errorf("technical asset %q communication link %q: %w", title, commLinkTitle, err)
	}
	usage, err := types.ParseUsage(commLink.Usage)
	if err != nil {
		return nil, fmt.Errorf("unknown 'usage' value of technical asset %q communication link %q: %v",
			title, commLinkTitle, commLink.Usage)
	}
	protocol, err := types.ParseProtocol(commLink.Protocol)
	if err != nil {
		return nil, fmt.Errorf("unknown 'protocol' value of technical asset %q communication link %q: %v",
			title, commLinkTitle, commLink.Protocol)
	}

	return &types.CommunicationLink{
		SourceId:               sourceId,
		TargetId:               commLink.Target,
		Title:                  commLinkTitle,
		Description:            withDefault(commLink.Description, commLinkTitle),
		Protocol:               protocol,
		Authentication:         authentication,
		Identity:               identity,
		Account:                strings.TrimSpace(commLink.Account),
		Authorization:          authorization,
		Usage:                  usage,
		VPN:                    commLink.VPN,
		IpFiltered:             commLink.IpFiltered,
		Readonly:               commLink.Readonly,
		DiagramTweakWeight:     1,
		DiagramTweakConstraint: !commLink.DiagramTweakConstraint,
	}, nil
}

// appendLinkDataAssets appends the data assets that a communication link sends or receives to the list,
// once each and after checking that they exist, and adds them to the data assets that its source
// processes.
func appendLinkDataAssets(
	parsedModel *types.Model, list []string, processed []string, references []string, where string,
) ([]string, []string, error) {
	for _, referencedAsset := range references {
		if contains(list, referencedAsset) {
			continue
		}

		err := parsedModel.CheckDataAssetTargetExists(referencedAsset, where)
		if err != nil {
			return nil, nil, err
		}
		list = append(list, referencedAsset)

		if !contains(processed, referencedAsset) {
			processed = append(processed, referencedAsset)
		}
	}
	return list, processed, nil
}

// addProxyHops gives the hops after the first one to the proxies, as if they were modelled as their links.
func (parser *technicalAssetParser) addProxyHops() {
	for _, hop := range parser.proxyHops {
		proxy := parser.parsedModel.TechnicalAssets[hop.SourceId]
		proxy.CommunicationLinks = append(proxy.CommunicationLinks, hop)
		for _, dataAsset := range slices.Concat(hop.DataAssetsSent, hop.DataAssetsReceived) {
			if !contains(proxy.DataAssetsProcessed, dataAsset) {
				proxy.DataAssetsProcessed = append(proxy.DataAssetsProcessed, dataAsset)
			}
		}
		addCommunicationLink(parser.parsedModel, hop)
		parser.hopOwners[proxy.Id] = true
	}
	// keep the links of the assets with hops ordered by title, like those of every other asset
	byTitle := func(a, b *types.CommunicationLink) int {
		return cmp.Or(strings.Compare(a.Title, b.Title), strings.Compare(a.Id, b.Id))
	}
	for ownerId := range parser.hopOwners {
		slices.SortStableFunc(parser.parsedModel.TechnicalAssets[ownerId].CommunicationLinks, byTitle)
	}
}

// raiseTechnicalAssetCIA raises the CIA rating of each technical asset that is lower than that of its data
// assets to the highest CIA value of its data assets.
func raiseTechnicalAssetCIA(parsedModel *types.Model) {
	for id, techAsset := range parsedModel.TechnicalAssets {
		dataAssetConfidentiality := parsedModel.HighestTechnicalAssetConfidentiality(techAsset)
		if techAsset.Confidentiality < dataAssetConfidentiality {
			techAsset.Confidentiality = dataAssetConfidentiality
		}

		dataAssetIntegrity := parsedModel.HighestIntegrity(techAsset)
		if techAsset.Integrity < dataAssetIntegrity {
			techAsset.Integrity = dataAssetIntegrity
		}

		dataAssetAvailability := parsedModel.HighestAvailability(techAsset)
		if techAsset.Availability < dataAssetAvailability {
			techAsset.Availability = dataAssetAvailability
		}

		parsedModel.TechnicalAssets[id] = techAsset
	}
}

// addDataAssetsProcessedByTargets makes the target of a communication link implicitly process all data
// assets that are sent to or received by that target.
func addDataAssetsProcessedByTargets(parsedModel *types.Model) error {
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		for _, commLink := range techAsset.CommunicationLinks {
			if commLink.TargetId == id {
				continue
			}
			targetTechAsset := parsedModel.TechnicalAssets[commLink.TargetId]
			if targetTechAsset == nil {
				return fmt.Errorf("missing target technical asset %q for communication link: %q",
					commLink.TargetId, commLink.Title)
			}
			dataAssetsProcessedByTarget := targetTechAsset.DataAssetsProcessed
			for _, dataAssetSent := range commLink.DataAssetsSent {
				if !contains(dataAssetsProcessedByTarget, dataAssetSent) {
					dataAssetsProcessedByTarget = append(dataAssetsProcessedByTarget, dataAssetSent)
				}
			}
			for _, dataAssetReceived := range commLink.DataAssetsReceived {
				if !contains(dataAssetsProcessedByTarget, dataAssetReceived) {
					dataAssetsProcessedByTarget = append(dataAssetsProcessedByTarget, dataAssetReceived)
				}
			}
			targetTechAsset.DataAssetsProcessed = dataAssetsProcessedByTarget
			parsedModel.TechnicalAssets[commLink.TargetId] = targetTechAsset
		}
	}
	return nil
}

// Trust Boundaries ===============================================================================

func parseTrustBoundaries(parsedModel *types.Model, modelInput *input.Model) error {
	checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries := make(map[string]bool)
	parsedModel.TrustBoundaries = make(map[string]*types.TrustBoundary)
	for _, title := range slices.Sorted(maps.Keys(modelInput.TrustBoundaries)) {
		trustBoundary, err := parseTrustBoundary(parsedModel, title, modelInput.TrustBoundaries[title],
			checklistToAvoidAssetBeingModeledInMultipleTrustBoundaries)
		if err != nil {
			return err
		}
		parsedModel.TrustBoundaries[trustBoundary.Id] = trustBoundary
		for _, technicalAsset := range trustBoundary.TechnicalAssetsInside {
			parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[technicalAsset] = trustBoundary
			// fmt.Println("Asset "+technicalAsset+" is directly in trust boundary "+trustBoundary.ID)
		}
	}
	nestingError := parsedModel.CheckNestedTrustBoundariesExisting()
	return nestingError
}

func parseTrustBoundary(
	parsedModel *types.Model, title string, boundary input.TrustBoundary, assetsInBoundaries map[string]bool,
) (*types.TrustBoundary, error) {
	id := boundary.ID

	technicalAssetsInside, err := parseTechnicalAssetsInside(parsedModel, title, boundary.TechnicalAssetsInside,
		assetsInBoundaries)
	if err != nil {
		return nil, err
	}

	trustBoundariesNested := make([]string, 0)
	if boundary.TrustBoundariesNested != nil {
		trustBoundariesNested = make([]string, len(boundary.TrustBoundariesNested))
		copy(trustBoundariesNested, boundary.TrustBoundariesNested)
	}

	trustBoundaryType, err := types.ParseTrustBoundary(boundary.Type)
	if err != nil {
		return nil, fmt.Errorf("unknown 'type' of trust boundary %q: %v", title, boundary.Type)
	}
	tags, err := parsedModel.CheckTags(lowerCaseAndTrim(boundary.Tags), fmt.Sprintf("trust boundary %q", title))
	if err != nil {
		return nil, err
	}
	networkPolicy, err := parseNetworkPolicy(title, boundary.NetworkPolicy, trustBoundaryType)
	if err != nil {
		return nil, err
	}
	trustBoundary := &types.TrustBoundary{
		Id:                    id,
		Title:                 title, // fmt.Sprintf("%v", boundary["title"]),
		Description:           withDefault(boundary.Description, title),
		Type:                  trustBoundaryType,
		Tags:                  tags,
		TechnicalAssetsInside: technicalAssetsInside,
		TrustBoundariesNested: trustBoundariesNested,
		NetworkPolicy:         networkPolicy,
	}
	err = checkIdSyntax(id)
	if err != nil {
		return nil, err
	}
	if _, exists := parsedModel.TrustBoundaries[id]; exists {
		return nil, fmt.Errorf("duplicate id used: %v", id)
	}
	return trustBoundary, nil
}

// parseNetworkPolicy parses the network policy of a trust boundary, which only a Kubernetes namespace, an execution
// environment, has.
func parseNetworkPolicy(
	title string, value string, boundaryType types.TrustBoundaryType,
) (types.NetworkPolicy, error) {
	networkPolicy, err := types.ParseNetworkPolicy(strings.TrimSpace(value))
	if err != nil {
		return networkPolicy, fmt.Errorf("unknown 'network_policy' of trust boundary %q: %v", title, value)
	}
	if networkPolicy != types.UnknownNetworkPolicy && boundaryType != types.ExecutionEnvironment {
		return networkPolicy, fmt.Errorf("'network_policy' of trust boundary %q needs the type %v, not %v: only "+
			"a Kubernetes namespace has network policies", title, types.ExecutionEnvironment, boundaryType)
	}
	return networkPolicy, nil
}

// parseTechnicalAssetsInside checks the technical assets inside a trust boundary, which may not be inside
// another trust boundary as well; assetsInBoundaries records the assets already inside one.
func parseTechnicalAssetsInside(
	parsedModel *types.Model, title string, parsedInsideAssets []string, assetsInBoundaries map[string]bool,
) ([]string, error) {
	technicalAssetsInside := make([]string, 0)
	if parsedInsideAssets != nil {
		technicalAssetsInside = make([]string, len(parsedInsideAssets))
		for i, parsedInsideAsset := range parsedInsideAssets {
			technicalAssetsInside[i] = strings.ToLower(parsedInsideAsset)
			_, found := parsedModel.TechnicalAssets[technicalAssetsInside[i]]
			if !found {
				return nil, fmt.Errorf("missing referenced technical asset %q at trust boundary %q",
					technicalAssetsInside[i], title)
			}
			if assetsInBoundaries[technicalAssetsInside[i]] {
				return nil, fmt.Errorf("referenced technical asset %q at trust boundary %q is modeled in multiple trust boundaries",
					technicalAssetsInside[i], title)
			}
			assetsInBoundaries[technicalAssetsInside[i]] = true
			// fmt.Println("asset "+technicalAssetsInside[i]+" at i="+strconv.Itoa(i))
		}
	}
	return technicalAssetsInside, nil
}

// Shared Runtime ===============================================================================

func parseSharedRuntimes(parsedModel *types.Model, modelInput *input.Model) error {
	parsedModel.SharedRuntimes = make(map[string]*types.SharedRuntime)
	for _, title := range slices.Sorted(maps.Keys(modelInput.SharedRuntimes)) {
		sharedRuntime, err := parseSharedRuntime(parsedModel, title, modelInput.SharedRuntimes[title])
		if err != nil {
			return err
		}
		parsedModel.SharedRuntimes[sharedRuntime.Id] = sharedRuntime
	}
	return nil
}

func parseSharedRuntime(
	parsedModel *types.Model, title string, inputRuntime input.SharedRuntime,
) (*types.SharedRuntime, error) {
	id := inputRuntime.ID

	technicalAssetsRunning := make([]string, 0)
	if inputRuntime.TechnicalAssetsRunning != nil {
		parsedRunningAssets := inputRuntime.TechnicalAssetsRunning
		technicalAssetsRunning = make([]string, len(parsedRunningAssets))
		for i, parsedRunningAsset := range parsedRunningAssets {
			assetId := parsedRunningAsset
			err := parsedModel.CheckTechnicalAssetExists(assetId, "shared runtime '"+title+"'", false)
			if err != nil {
				return nil, err
			}
			technicalAssetsRunning[i] = assetId
		}
	}
	tags, err := parsedModel.CheckTags(lowerCaseAndTrim(inputRuntime.Tags), "shared runtime '"+title+"'")
	if err != nil {
		return nil, err
	}
	sharedRuntime := &types.SharedRuntime{
		Id:                     id,
		Title:                  title, // fmt.Sprintf("%v", boundary["title"]),
		Description:            withDefault(inputRuntime.Description, title),
		Tags:                   tags,
		TechnicalAssetsRunning: technicalAssetsRunning,
	}
	err = checkIdSyntax(id)
	if err != nil {
		return nil, err
	}
	if _, exists := parsedModel.SharedRuntimes[id]; exists {
		return nil, fmt.Errorf("duplicate id used: %v", id)
	}
	return sharedRuntime, nil
}

// Risk Categories ===============================================================================

// addRiskRuleCategories adds the categories of the built-in and the custom risk rules, ordered by rule id.
func addRiskRuleCategories(
	parsedModel *types.Model, builtinRiskRules types.RiskRules, customRiskRules types.RiskRules,
) {
	for _, id := range slices.Sorted(maps.Keys(builtinRiskRules)) {
		parsedModel.BuiltInRiskCategories = append(parsedModel.BuiltInRiskCategories, builtinRiskRules[id].Category())
	}

	for _, id := range slices.Sorted(maps.Keys(customRiskRules)) {
		parsedModel.CustomRiskCategories = append(parsedModel.CustomRiskCategories, customRiskRules[id].Category())
	}
}

// Individual Risk Categories (just used as regular risk categories) ===============================================

func parseCustomRiskCategories(parsedModel *types.Model, modelInput *input.Model) error {
	for _, customRiskCategoryCategory := range modelInput.CustomRiskCategories {
		err := parseCustomRiskCategory(parsedModel, customRiskCategoryCategory)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseCustomRiskCategory(parsedModel *types.Model, customRiskCategoryCategory *input.RiskCategory) error {
	function, err := types.ParseRiskFunction(customRiskCategoryCategory.Function)
	if err != nil {
		return fmt.Errorf("unknown 'function' value of individual risk category %q: %v",
			customRiskCategoryCategory.Title, customRiskCategoryCategory.Function)
	}

	stride, err := types.ParseSTRIDE(customRiskCategoryCategory.STRIDE)
	if err != nil {
		return fmt.Errorf("unknown 'stride' value of individual risk category  %q: %v",
			customRiskCategoryCategory.Title, customRiskCategoryCategory.STRIDE)
	}

	cat := &types.RiskCategory{
		ID:                         customRiskCategoryCategory.ID,
		Title:                      withDefault(customRiskCategoryCategory.Title, customRiskCategoryCategory.ID),
		Description:                customRiskCategoryCategory.Description,
		Impact:                     customRiskCategoryCategory.Impact,
		ASVS:                       customRiskCategoryCategory.ASVS,
		CheatSheet:                 customRiskCategoryCategory.CheatSheet,
		Action:                     customRiskCategoryCategory.Action,
		Mitigation:                 customRiskCategoryCategory.Mitigation,
		Check:                      customRiskCategoryCategory.Check,
		DetectionLogic:             customRiskCategoryCategory.DetectionLogic,
		RiskAssessment:             customRiskCategoryCategory.RiskAssessment,
		FalsePositives:             customRiskCategoryCategory.FalsePositives,
		Function:                   function,
		STRIDE:                     stride,
		ModelFailurePossibleReason: customRiskCategoryCategory.ModelFailurePossibleReason,
		CWE:                        customRiskCategoryCategory.CWE,
		References:                 customRiskCategoryCategory.References,
	}

	// the reports name a category by its title, which the map key of individual_risk_categories
	// used to be (threagile#130)
	if cat.Description == "" {
		cat.Description = cat.Title
	}

	err = checkIdSyntax(customRiskCategoryCategory.ID)
	if err != nil {
		return err
	}

	if !parsedModel.CustomRiskCategories.Add(cat) {
		return fmt.Errorf("duplicate id used: %v", customRiskCategoryCategory.ID)
	}

	// NOW THE INDIVIDUAL RISK INSTANCES:
	// individualRiskInstances := make([]model.Risk, 0)
	// a synthetic id that another risk already uses is not reported yet
	for _, title := range slices.Sorted(maps.Keys(customRiskCategoryCategory.RisksIdentified)) {
		risk, err := parseIndividualRisk(parsedModel, cat.ID, title, customRiskCategoryCategory.RisksIdentified[title])
		if err != nil {
			return err
		}
		parsedModel.GeneratedRisksByCategory[cat.ID] = append(parsedModel.GeneratedRisksByCategory[cat.ID], risk)
	}
	return nil
}

func parseIndividualRisk(
	parsedModel *types.Model, categoryId string, title string, individualRiskInstance input.RiskIdentified,
) (*types.Risk, error) {
	severity, err := types.ParseRiskSeverity(individualRiskInstance.Severity)
	if err != nil {
		return nil, fmt.Errorf("unknown 'severity' value of individual risk instance %q: %v",
			title, individualRiskInstance.Severity)
	}
	exploitationLikelihood, err := types.ParseRiskExploitationLikelihood(individualRiskInstance.ExploitationLikelihood)
	if err != nil {
		return nil, fmt.Errorf("unknown 'exploitation_likelihood' value of individual risk instance %q: %v",
			title, individualRiskInstance.ExploitationLikelihood)
	}
	exploitationImpact, err := types.ParseRiskExploitationImpact(individualRiskInstance.ExploitationImpact)
	if err != nil {
		return nil, fmt.Errorf("unknown 'exploitation_impact' value of individual risk instance %q: %v",
			title, individualRiskInstance.ExploitationImpact)
	}

	err = checkIndividualRiskReferences(parsedModel, title, individualRiskInstance)
	if err != nil {
		return nil, err
	}

	dataBreachProbability, err := types.ParseDataBreachProbability(individualRiskInstance.DataBreachProbability)
	if err != nil {
		return nil, fmt.Errorf("unknown 'data_breach_probability' value of individual risk instance %q: %v",
			title, individualRiskInstance.DataBreachProbability)
	}

	dataBreachTechnicalAssetIDs, err := parseDataBreachTechnicalAssets(parsedModel, title,
		individualRiskInstance.DataBreachTechnicalAssets)
	if err != nil {
		return nil, err
	}

	mostRelevantDataAssetId := individualRiskInstance.MostRelevantDataAsset
	mostRelevantTechnicalAssetId := individualRiskInstance.MostRelevantTechnicalAsset
	mostRelevantCommunicationLinkId := individualRiskInstance.MostRelevantCommunicationLink
	mostRelevantTrustBoundaryId := individualRiskInstance.MostRelevantTrustBoundary
	mostRelevantSharedRuntimeId := individualRiskInstance.MostRelevantSharedRuntime
	return &types.Risk{
		SyntheticId: createSyntheticId(categoryId, mostRelevantDataAssetId, mostRelevantTechnicalAssetId,
			mostRelevantCommunicationLinkId, mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId),
		Title:                           title,
		CategoryId:                      categoryId,
		Severity:                        severity,
		ExploitationLikelihood:          exploitationLikelihood,
		ExploitationImpact:              exploitationImpact,
		MostRelevantDataAssetId:         mostRelevantDataAssetId,
		MostRelevantTechnicalAssetId:    mostRelevantTechnicalAssetId,
		MostRelevantCommunicationLinkId: mostRelevantCommunicationLinkId,
		MostRelevantTrustBoundaryId:     mostRelevantTrustBoundaryId,
		MostRelevantSharedRuntimeId:     mostRelevantSharedRuntimeId,
		DataBreachProbability:           dataBreachProbability,
		DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
	}, nil
}

// checkIndividualRiskReferences checks that the most relevant elements an individual risk names exist.
func checkIndividualRiskReferences(
	parsedModel *types.Model, title string, individualRiskInstance input.RiskIdentified,
) error {
	checkTechnicalAssetExists := func(referencedAsset, where string) error {
		return parsedModel.CheckTechnicalAssetExists(referencedAsset, where, false)
	}
	references := []struct {
		id    string
		check func(referencedId, where string) error
	}{
		{individualRiskInstance.MostRelevantDataAsset, parsedModel.CheckDataAssetTargetExists},
		{individualRiskInstance.MostRelevantTechnicalAsset, checkTechnicalAssetExists},
		{individualRiskInstance.MostRelevantCommunicationLink, parsedModel.CheckCommunicationLinkExists},
		{individualRiskInstance.MostRelevantTrustBoundary, parsedModel.CheckTrustBoundaryExists},
		{individualRiskInstance.MostRelevantSharedRuntime, parsedModel.CheckSharedRuntimeExists},
	}
	for _, reference := range references {
		if len(reference.id) == 0 {
			continue
		}
		err := reference.check(reference.id, fmt.Sprintf("individual risk %q", title))
		if err != nil {
			return err
		}
	}
	return nil
}

func parseDataBreachTechnicalAssets(
	parsedModel *types.Model, title string, referencedAssets []string,
) ([]string, error) {
	var dataBreachTechnicalAssetIDs []string
	if referencedAssets != nil {
		dataBreachTechnicalAssetIDs = make([]string, len(referencedAssets))
		for i, parsedReferencedAsset := range referencedAssets {
			assetId := parsedReferencedAsset
			err := parsedModel.CheckTechnicalAssetExists(assetId,
				fmt.Sprintf("data breach technical assets of individual risk %q", title), false)
			if err != nil {
				return nil, err
			}
			dataBreachTechnicalAssetIDs[i] = assetId
		}
	}
	return dataBreachTechnicalAssetIDs, nil
}

// Risk Tracking ===============================================================================

func parseRiskTracking(parsedModel *types.Model, modelInput *input.Model) error {
	parsedModel.RiskTracking = make(map[string]*types.RiskTracking)
	for syntheticRiskId, riskTracking := range modelInput.RiskTracking {
		justification := riskTracking.Justification
		checkedBy := riskTracking.CheckedBy
		ticket := riskTracking.Ticket
		var date time.Time
		if len(riskTracking.Date) > 0 {
			var parseError error
			date, parseError = time.Parse("2006-01-02", riskTracking.Date)
			if parseError != nil {
				return fmt.Errorf("unable to parse 'date' of risk tracking %q: %v", syntheticRiskId, riskTracking.Date)
			}
		}

		status, err := types.ParseRiskStatus(riskTracking.Status)
		if err != nil {
			return fmt.Errorf("unknown 'status' value of risk tracking %q: %v", syntheticRiskId, riskTracking.Status)
		}

		tracking := &types.RiskTracking{
			SyntheticRiskId: strings.TrimSpace(syntheticRiskId),
			Justification:   justification,
			CheckedBy:       checkedBy,
			Ticket:          ticket,
			Date:            types.Date{Time: date},
			Status:          status,
		}

		parsedModel.RiskTracking[syntheticRiskId] = tracking
	}
	return nil
}

// checkCommunicationLinkTargets checks the model for consistency: the target of every communication link
// has to exist.
func checkCommunicationLinkTargets(parsedModel *types.Model) error {
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		for _, commLink := range technicalAsset.CommunicationLinks {
			err := parsedModel.CheckTechnicalAssetExists(commLink.TargetId,
				"communication link '"+commLink.Title+"' of technical asset '"+technicalAsset.Title+"'", false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func convertAuthor(author input.Author) *types.Author {
	return &types.Author{
		Name:     author.Name,
		Contact:  author.Contact,
		Homepage: author.Homepage,
	}
}

func convertAuthors(authors []input.Author) []*types.Author {
	result := make([]*types.Author, len(authors))
	for i, author := range authors {
		result[i] = convertAuthor(author)
	}
	return result
}

func checkIdSyntax(id string) error {
	validIdSyntax := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
	if !validIdSyntax.MatchString(id) {
		return fmt.Errorf("invalid id syntax used (only letters, numbers, and hyphen allowed): %v", id)
	}
	return nil
}

func createDataFlowId(sourceAssetId, title string) string {
	reg := regexp.MustCompile("[^A-Za-z0-9]+")
	return sourceAssetId + ">" + strings.Trim(reg.ReplaceAllString(strings.ToLower(title), "-"), "- ")
}

// addCommunicationLink tracks a link of a technical asset in the indexes of all links.
func addCommunicationLink(parsedModel *types.Model, link *types.CommunicationLink) {
	// track all comm links
	parsedModel.CommunicationLinks[link.Id] = link
	// keep track of map of *all* comm links mapped by target-id (to be able to look up "who is calling me" kind of things)
	parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId] = append(
		parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId], link)
}

// expandVia splits a communication link through proxies, the technical assets its via lists in order,
// into one link per hop: from the source of the link to the first proxy, from there to the next one,
// and from the last proxy to the target of the link. Every hop copies the attributes of the link.
// The id of a hop is the id of the link followed by ">" and the id of the target of the hop, so it
// cannot clash with the id of a modelled link, which has a single ">". Its title is the title of the
// link followed by "(hop 2 of 3)".
func expandVia(
	link *types.CommunicationLink, via []string, technicalAssetIds map[string]bool, where string,
) ([]*types.CommunicationLink, error) {
	for i, proxyId := range via {
		switch {
		case !technicalAssetIds[proxyId]:
			return nil, fmt.Errorf("missing technical asset %q in 'via' of %s", proxyId, where)
		case proxyId == link.SourceId:
			return nil, fmt.Errorf("'via' of %s lists its source %q", where, proxyId)
		case proxyId == link.TargetId:
			return nil, fmt.Errorf("'via' of %s lists its target %q", where, proxyId)
		case slices.Contains(via[:i], proxyId):
			return nil, fmt.Errorf("'via' of %s lists %q more than once", where, proxyId)
		}
	}

	stops := slices.Concat([]string{link.SourceId}, via, []string{link.TargetId})
	hops := make([]*types.CommunicationLink, 0, len(stops)-1)
	for i := 1; i < len(stops); i++ {
		hop := *link
		hop.Id = link.Id + ">" + stops[i]
		hop.SourceId = stops[i-1]
		hop.TargetId = stops[i]
		hop.Title = fmt.Sprintf("%s (hop %d of %d)", link.Title, i, len(stops)-1)
		hop.Tags = slices.Clone(link.Tags)
		hop.DataAssetsSent = slices.Clone(link.DataAssetsSent)
		hop.DataAssetsReceived = slices.Clone(link.DataAssetsReceived)
		hops = append(hops, &hop)
	}
	return hops, nil
}

func createSyntheticId(categoryId string,
	mostRelevantDataAssetId, mostRelevantTechnicalAssetId, mostRelevantCommunicationLinkId string,
	mostRelevantTrustBoundaryId, mostRelevantSharedRuntimeId string,
) string {
	result := categoryId
	if len(mostRelevantTechnicalAssetId) > 0 {
		result += "@" + mostRelevantTechnicalAssetId
	}
	if len(mostRelevantCommunicationLinkId) > 0 {
		result += "@" + mostRelevantCommunicationLinkId
	}
	if len(mostRelevantTrustBoundaryId) > 0 {
		result += "@" + mostRelevantTrustBoundaryId
	}
	if len(mostRelevantSharedRuntimeId) > 0 {
		result += "@" + mostRelevantSharedRuntimeId
	}
	if len(mostRelevantDataAssetId) > 0 {
		result += "@" + mostRelevantDataAssetId
	}
	return result
}

// in order to prevent Path-Traversal like stuff...
func removePathElementsFromImageFiles(overview input.Overview) *types.Overview {
	parsedOverview := &types.Overview{
		Description: overview.Description,
		Images:      make([]map[string]string, len(overview.Images)),
	}
	for i := range overview.Images {
		newValue := make(map[string]string)
		for file, desc := range overview.Images[i] {
			newValue[filepath.Base(file)] = desc
		}
		parsedOverview.Images[i] = newValue
	}
	return parsedOverview
}

func withDefault(value string, defaultWhenEmpty string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) > 0 && trimmed != "<nil>" {
		return trimmed
	}
	return strings.TrimSpace(defaultWhenEmpty)
}

func lowerCaseAndTrim(tags []string) []string {
	for i := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(tags[i]))
	}
	return tags
}

func contains(a []string, x string) bool {
	return slices.Contains(a, x)
}
