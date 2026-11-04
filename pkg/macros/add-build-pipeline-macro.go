package macros

import (
	"strings"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

type AddBuildPipeline struct {
	macroState             map[string][]string
	questionsAnswered      []string
	codeInspectionUsed     bool
	containerTechUsed      bool
	withinTrustBoundary    bool
	createNewTrustBoundary bool
}

func NewBuildPipeline() *AddBuildPipeline {
	return &AddBuildPipeline{
		macroState:        make(map[string][]string),
		questionsAnswered: make([]string, 0),
	}
}

var pushOrPull = []string{
	"Push-based Deployment (build pipeline deploys towards target asset)",
	"Pull-based Deployment (deployment target asset fetches deployment from registry)",
}

func (m *AddBuildPipeline) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:    "add-build-pipeline",
		Title: "Add Build Pipeline",
		Description: "This model macro adds a build pipeline (development client, build pipeline, artifact registry, " +
			"container image registry, source code repository, etc.) to the model.",
	}
}

// The macro does not ask for the type of machine (physical, virtual, container, etc.) of the assets yet.

// The questions of the build pipeline macro by their number; questions 11 and 13 depend on the model.
var buildPipelineQuestions = map[int]MacroQuestion{
	0: {
		ID:              "source-repository",
		Title:           "What product is used as the sourcecode repository?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "Git",
	},
	1: {
		ID:              "build-pipeline",
		Title:           "What product is used as the build pipeline?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "Jenkins",
	},
	2: {
		ID:              "artifact-registry",
		Title:           "What product is used as the artifact registry?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "Nexus",
	},
	3: {
		ID:              "code-inspection-used",
		Title:           "Are code inspection platforms (like SonarQube) used?",
		Description:     "This affects whether code inspection platform are added.",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerYes,
	},
	4: {
		ID:              types.CodeInspectionPlatform,
		Title:           "What product is used as the code inspection platform?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "SonarQube",
	},
	5: {
		ID:              "container-technology-used",
		Title:           "Is container technology (like Docker) used?",
		Description:     "This affects whether container registries are added.",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerYes,
	},
	6: {
		ID:              "container-registry",
		Title:           "What product is used as the container registry?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "Docker",
	},
	7: {
		ID:              "container-platform",
		Title:           "What product is used as the container platform (for orchestration and runtime)?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "Kubernetes",
	},
	8: {
		ID:              "internet",
		Title:           "Are build pipeline components exposed on the internet?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerNo,
	},
	9: {
		ID:              "multi-tenant",
		Title:           "Are build pipeline components used by multiple tenants?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerNo,
	},
	10: {
		ID:              "encryption",
		Title:           "Are build pipeline components encrypted?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerNo,
	},
	12: {
		ID:              withinTrustBoundaryQuestion,
		Title:           "Are the server-side components of the build pipeline components within a network trust boundary?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerYes,
	},
	14: newTrustBoundaryTypeQuestion,
	15: {
		ID:              "push-or-pull",
		Title:           "What type of deployment strategy is used?",
		Description:     "Push-based deployments are more classic ones and pull-based are more GitOps-like ones.",
		PossibleAnswers: pushOrPull,
		MultiSelect:     false,
		DefaultAnswer:   "",
	},
	16: {
		ID:              "owner",
		Title:           "Who is the owner of the build pipeline and runtime assets?",
		Description:     "This name affects the technical asset's and data asset's owner.",
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	},
}

// The numbers of the questions of the build pipeline macro that depend on the model.
const (
	deployTargetsQuestionNumber       = 11
	selectTrustBoundaryQuestionNumber = 13
)

func (m *AddBuildPipeline) GetNextQuestion(model *types.Model) (nextQuestion MacroQuestion, err error) {
	counter := m.nextQuestionNumber()
	switch counter {
	case deployTargetsQuestionNumber:
		return technicalAssetsQuestion(model, "deploy-targets",
			"Select all technical assets where the build pipeline deploys to:"), nil
	case selectTrustBoundaryQuestionNumber:
		return selectTrustBoundaryQuestion(model), nil
	}
	if question, ok := buildPipelineQuestions[counter]; ok {
		return question, nil
	}
	return NoMoreQuestions(), nil
}

// nextQuestionNumber counts the questions answered so far, and those skipped by the answers.
func (m *AddBuildPipeline) nextQuestionNumber() int {
	counter := len(m.questionsAnswered)
	if counter > 3 && !m.codeInspectionUsed {
		counter++
	}
	if counter > 5 && !m.containerTechUsed {
		counter += 2
	}
	if counter > 12 && !m.withinTrustBoundary {
		counter++
	}
	if counter > 13 && !m.createNewTrustBoundary {
		counter++
	}
	return counter
}

func (m *AddBuildPipeline) ApplyAnswer(
	questionID string, answer ...string,
) (message string, validResult bool, err error) {
	m.macroState[questionID] = answer
	m.questionsAnswered = append(m.questionsAnswered, questionID)
	switch questionID {
	case "code-inspection-used":
		m.codeInspectionUsed = strings.EqualFold(m.macroState["code-inspection-used"][0], "yes")
	case "container-technology-used":
		m.containerTechUsed = strings.EqualFold(m.macroState["container-technology-used"][0], "yes")
	case withinTrustBoundaryQuestion:
		m.withinTrustBoundary = strings.EqualFold(m.macroState[withinTrustBoundaryQuestion][0], "yes")
	case selectedTrustBoundaryQuestion:
		m.createNewTrustBoundary = strings.EqualFold(m.macroState[selectedTrustBoundaryQuestion][0],
			createNewTrustBoundaryLabel)
	}

	return answerProcessed, true, nil
}

func (m *AddBuildPipeline) GoBack() (message string, validResult bool, err error) {
	if len(m.questionsAnswered) == 0 {
		return cannotGoBackFurther, false, nil
	}
	lastQuestionID := m.questionsAnswered[len(m.questionsAnswered)-1]
	m.questionsAnswered = m.questionsAnswered[:len(m.questionsAnswered)-1]
	delete(m.macroState, lastQuestionID)
	return "Undo successful", true, nil
}

func (m *AddBuildPipeline) GetFinalChangeImpact(
	modelInput *input.Model, model *types.Model,
) (changes []string, message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult = m.applyChange(modelInput, model, &changeLogCollector, true)
	return changeLogCollector, message, validResult, nil
}

func (m *AddBuildPipeline) Execute(
	modelInput *input.Model, model *types.Model,
) (message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult = m.applyChange(modelInput, model, &changeLogCollector, false)
	return message, validResult, nil
}

// buildPipelineChange applies the answers of the build pipeline macro to a model, or for a dry run only
// collects the changes it would make.
type buildPipelineChange struct {
	*AddBuildPipeline
	modelInput         *input.Model
	parsedModel        *types.Model
	changeLogCollector *[]string
	dryRun             bool

	sourceRepoID, buildPipelineID, artifactRegistryID              string
	containerRepoID, containerPlatformID, containerSharedRuntimeID string
	codeInspectionPlatformID                                       string
	owner                                                          string

	// the server-side technical assets the macro adds, which it places in a trust boundary
	serverSideTechAssets []string
}

func (m *AddBuildPipeline) applyChange(
	modelInput *input.Model, parsedModel *types.Model, changeLogCollector *[]string, dryRun bool,
) (message string, validResult bool) {
	change := &buildPipelineChange{
		AddBuildPipeline:     m,
		modelInput:           modelInput,
		parsedModel:          parsedModel,
		changeLogCollector:   changeLogCollector,
		dryRun:               dryRun,
		serverSideTechAssets: make([]string, 0),
	}
	// ################################################
	change.addTags()
	change.initIDs()

	change.addDataAsset("Sourcecode", input.DataAsset{
		ID:              sourcecodeDataAsset,
		Description:     "Sourcecode to build the application components from",
		Usage:           types.DevOps.String(),
		Tags:            []string{},
		Origin:          "",
		Owner:           change.owner,
		Quantity:        types.Few.String(),
		Confidentiality: types.Confidential.String(),
		Integrity:       types.Critical.String(),
		Availability:    types.Important.String(),
		JustificationCiaRating: "Sourcecode is at least rated as 'critical' in terms of integrity, because any " +
			"malicious modification of it might lead to a backdoored production system.",
	})
	change.addDataAsset("Deployment", input.DataAsset{
		ID:              deploymentDataAsset,
		Description:     "Deployment unit being installed/shipped",
		Usage:           types.DevOps.String(),
		Tags:            []string{},
		Origin:          "",
		Owner:           change.owner,
		Quantity:        types.VeryFew.String(),
		Confidentiality: types.Confidential.String(),
		Integrity:       types.Critical.String(),
		Availability:    types.Important.String(),
		JustificationCiaRating: "Deployment units are at least rated as 'critical' in terms of integrity, because any " +
			"malicious modification of it might lead to a backdoored production system.",
	})

	change.addDevelopmentClient()
	change.addSourceRepository()
	if m.containerTechUsed {
		change.addContainerAssets()
	}
	change.addBuildPipeline()
	change.addArtifactRegistry()
	if m.codeInspectionUsed {
		change.addCodeInspectionPlatform()
	}
	if m.withinTrustBoundary {
		change.addToTrustBoundary()
	}
	if m.containerTechUsed {
		change.addSharedRuntime()
	}

	return changesetValid, true
}

func (change *buildPipelineChange) answer(questionID string) string {
	return change.macroState[questionID][0]
}

func (change *buildPipelineChange) answeredYes(questionID string) bool {
	return strings.EqualFold(change.answer(questionID), "yes")
}

func (change *buildPipelineChange) logChange(text string) {
	*change.changeLogCollector = append(*change.changeLogCollector, text)
}

func (change *buildPipelineChange) addTags() {
	change.modelInput.AddTagToModelInput(change.answer("source-repository"), change.dryRun, change.changeLogCollector)
	change.modelInput.AddTagToModelInput(change.answer("build-pipeline"), change.dryRun, change.changeLogCollector)
	change.modelInput.AddTagToModelInput(change.answer("artifact-registry"), change.dryRun, change.changeLogCollector)
	if change.containerTechUsed {
		change.modelInput.AddTagToModelInput(change.answer("container-registry"), change.dryRun,
			change.changeLogCollector)
		change.modelInput.AddTagToModelInput(change.answer("container-platform"), change.dryRun,
			change.changeLogCollector)
	}
	if change.codeInspectionUsed {
		change.modelInput.AddTagToModelInput(change.answer(types.CodeInspectionPlatform), change.dryRun,
			change.changeLogCollector)
	}
}

func (change *buildPipelineChange) initIDs() {
	change.sourceRepoID = types.MakeID(change.answer("source-repository")) + "-sourcecode-repository"
	change.buildPipelineID = types.MakeID(change.answer("build-pipeline")) + "-build-pipeline"
	change.artifactRegistryID = types.MakeID(change.answer("artifact-registry")) + "-artifact-registry"
	if change.containerTechUsed {
		change.containerRepoID = types.MakeID(change.answer("container-registry")) + "-container-registry"
		change.containerPlatformID = types.MakeID(change.answer("container-platform")) + "-container-platform"
		change.containerSharedRuntimeID = types.MakeID(change.answer("container-platform")) + "-container-runtime"
	}
	if change.codeInspectionUsed {
		change.codeInspectionPlatformID = types.MakeID(change.answer(types.CodeInspectionPlatform)) +
			"-code-inspection-platform"
	}
	change.owner = change.answer("owner")
}

// addDataAsset adds a data asset under its title unless the model has it already.
func (change *buildPipelineChange) addDataAsset(title string, dataAsset input.DataAsset) {
	if _, exists := change.parsedModel.DataAssets[dataAsset.ID]; exists {
		return
	}
	change.logChange("adding data asset: " + dataAsset.ID)
	if !change.dryRun {
		change.modelInput.DataAssets[title] = dataAsset
	}
}

func (change *buildPipelineChange) encryption() string {
	if change.answeredYes("encryption") {
		return types.Transparent.String()
	}
	return types.NoneEncryption.String()
}

// devOpsLink is an HTTPS communication link of the build pipeline that authenticates with credentials.
func devOpsLink(
	target string, description string, authorization types.Authorization, readonly bool, sent []string,
	received []string,
) input.CommunicationLink {
	return input.CommunicationLink{
		Target:                 target,
		Description:            description,
		Protocol:               types.HTTPS.String(),
		Authentication:         types.Credentials.String(),
		Authorization:          authorization.String(),
		Tags:                   []string{},
		VPN:                    false,
		IpFiltered:             false,
		Readonly:               readonly,
		Usage:                  types.DevOps.String(),
		DataAssetsSent:         sent,
		DataAssetsReceived:     received,
		DiagramTweakWeight:     0,
		DiagramTweakConstraint: false,
	}
}

func (change *buildPipelineChange) addDevelopmentClient() {
	id := "development-client"
	if _, exists := change.parsedModel.TechnicalAssets[id]; exists {
		return
	}
	// fmt.Println("Adding technical asset:", id) // ################################################
	userIdentity := types.EndUserIdentityPropagation
	commLinks := make(map[string]input.CommunicationLink)
	commLinks["Sourcecode Repository Traffic"] = devOpsLink(change.sourceRepoID, "Sourcecode Repository Traffic",
		userIdentity, false, []string{sourcecodeDataAsset}, []string{sourcecodeDataAsset})
	commLinks["Build Pipeline Traffic"] = devOpsLink(change.buildPipelineID, "Build Pipeline Traffic",
		userIdentity, true, nil, []string{deploymentDataAsset})
	commLinks["Artifact Registry Traffic"] = devOpsLink(change.artifactRegistryID, "Artifact Registry Traffic",
		userIdentity, true, nil, []string{deploymentDataAsset})
	if change.containerTechUsed {
		commLinks["Container Registry Traffic"] = devOpsLink(change.containerRepoID, "Container Registry Traffic",
			userIdentity, false, []string{deploymentDataAsset}, []string{deploymentDataAsset})
		commLinks["Container Platform Traffic"] = devOpsLink(change.containerPlatformID, "Container Platform Traffic",
			userIdentity, false, []string{deploymentDataAsset}, []string{deploymentDataAsset})
	}
	if change.codeInspectionUsed {
		commLinks["Code Inspection Platform Traffic"] = devOpsLink(change.codeInspectionPlatformID,
			"Code Inspection Platform Traffic", userIdentity, true, nil, []string{sourcecodeDataAsset})
	}

	techAsset := input.TechnicalAsset{
		ID:                      id,
		Description:             "Development Client",
		Type:                    types.ExternalEntity.String(),
		Usage:                   types.DevOps.String(),
		UsedAsClientByHuman:     true,
		OutOfScope:              true,
		JustificationOutOfScope: "Development client is not directly in-scope of the application.",
		Size:                    types.System.String(),
		Technology:              types.DevOpsClient,
		Tags:                    []string{},
		Internet:                change.answeredYes("internet"),
		Machine:                 types.Physical.String(),
		Encryption:              change.encryption(),
		Owner:                   change.owner,
		Confidentiality:         types.Confidential.String(),
		Integrity:               types.Critical.String(),
		Availability:            types.Important.String(),
		JustificationCiaRating: "Sourcecode processing components are at least rated as 'critical' in terms of " +
			"integrity, because any malicious modification of it might lead to a backdoored production system.",
		MultiTenant:          false,
		Redundant:            false,
		CustomDevelopedParts: false,
		DataAssetsProcessed:  []string{sourcecodeDataAsset, deploymentDataAsset},
		DataAssetsStored:     []string{sourcecodeDataAsset, deploymentDataAsset},
		DataFormatsAccepted:  []string{types.File.String()},
		CommunicationLinks:   commLinks,
	}
	change.logChange("adding technical asset (including communication links): " + id)
	if !change.dryRun {
		change.modelInput.TechnicalAssets["Development Client"] = techAsset
	}
}

// serverSideAsset starts a server-side technical asset of the build pipeline, named after the product that
// the answer to the question names.
func (change *buildPipelineChange) serverSideAsset(
	id string, productQuestion string, kind string, technology string,
) input.TechnicalAsset {
	return input.TechnicalAsset{
		ID:                      id,
		Description:             change.answer(productQuestion) + " " + kind,
		Type:                    types.Process.String(),
		Usage:                   types.DevOps.String(),
		UsedAsClientByHuman:     false,
		OutOfScope:              false,
		JustificationOutOfScope: "",
		Size:                    types.Service.String(),
		Technology:              technology,
		Tags:                    []string{input.NormalizeTag(change.answer(productQuestion))},
		Internet:                change.answeredYes("internet"),
		Machine:                 types.Virtual.String(),
		Encryption:              change.encryption(),
		Owner:                   change.owner,
		Confidentiality:         types.Confidential.String(),
		Integrity:               types.Critical.String(),
		Availability:            types.Important.String(),
		MultiTenant:             change.answeredYes("multi-tenant"),
		Redundant:               false,
		CustomDevelopedParts:    false,
		DataFormatsAccepted:     []string{types.File.String()},
		CommunicationLinks:      nil,
	}
}

// addServerSideAsset adds a server-side technical asset under its title, which its description is.
func (change *buildPipelineChange) addServerSideAsset(techAsset input.TechnicalAsset) {
	change.serverSideTechAssets = append(change.serverSideTechAssets, techAsset.ID)
	change.logChange("adding technical asset (including communication links): " + techAsset.ID)
	if !change.dryRun {
		change.modelInput.TechnicalAssets[techAsset.Description] = techAsset
	}
}

func (change *buildPipelineChange) exists(id string) bool {
	_, exists := change.parsedModel.TechnicalAssets[id]
	return exists
}

func (change *buildPipelineChange) addSourceRepository() {
	if change.exists(change.sourceRepoID) {
		return
	}
	// fmt.Println("Adding technical asset:", id) // ################################################
	techAsset := change.serverSideAsset(change.sourceRepoID, "source-repository", "Sourcecode Repository",
		types.SourcecodeRepository)
	techAsset.JustificationCiaRating = "Sourcecode processing components are at least rated as 'critical' in terms " +
		"of integrity, because any malicious modification of it might lead to a backdoored production system."
	techAsset.DataAssetsProcessed = []string{sourcecodeDataAsset}
	techAsset.DataAssetsStored = []string{sourcecodeDataAsset}
	change.addServerSideAsset(techAsset)
}

func (change *buildPipelineChange) addContainerAssets() {
	if !change.exists(change.containerRepoID) {
		// fmt.Println("Adding technical asset:", id) // ################################################
		techAsset := change.serverSideAsset(change.containerRepoID, "container-registry", "Container Registry",
			types.ArtifactRegistry)
		techAsset.JustificationCiaRating = "Container registry components are at least rated as 'critical' in " +
			"terms of integrity, because any malicious modification of it might lead to a backdoored production system."
		techAsset.DataAssetsProcessed = []string{deploymentDataAsset}
		techAsset.DataAssetsStored = []string{deploymentDataAsset}
		change.addServerSideAsset(techAsset)
	}

	if !change.exists(change.containerPlatformID) {
		// fmt.Println("Adding technical asset:", id) // ################################################
		techAsset := change.serverSideAsset(change.containerPlatformID, "container-platform", "Container Platform",
			types.ContainerPlatform)
		techAsset.Size = types.System.String()
		techAsset.Integrity = types.MissionCritical.String()
		techAsset.Availability = types.MissionCritical.String()
		techAsset.JustificationCiaRating = "Container platform components are rated as 'mission-critical' in terms " +
			"of integrity and availability, because any malicious modification of it might lead to a backdoored " +
			"production system."
		techAsset.DataAssetsProcessed = []string{deploymentDataAsset}
		techAsset.DataAssetsStored = []string{deploymentDataAsset}
		change.addServerSideAsset(techAsset)
	}
}

func (change *buildPipelineChange) addBuildPipeline() {
	if change.exists(change.buildPipelineID) {
		return
	}
	// fmt.Println("Adding technical asset:", id) // ################################################
	technicalUser := types.TechnicalUser
	commLinks := make(map[string]input.CommunicationLink)
	commLinks["Sourcecode Repository Traffic"] = devOpsLink(change.sourceRepoID, "Sourcecode Repository Traffic",
		technicalUser, true, nil, []string{sourcecodeDataAsset})
	commLinks["Artifact Registry Traffic"] = devOpsLink(change.artifactRegistryID, "Artifact Registry Traffic",
		technicalUser, false, []string{deploymentDataAsset}, []string{deploymentDataAsset})
	if change.containerTechUsed {
		change.addContainerPlatformLinks(commLinks)
	}
	if change.codeInspectionUsed {
		commLinks["Code Inspection Platform Traffic"] = devOpsLink(change.codeInspectionPlatformID,
			"Code Inspection Platform Traffic", technicalUser, false, []string{sourcecodeDataAsset}, []string{})
	}
	// The individual deployments
	for _, deployTargetID := range change.macroState["deploy-targets"] { // add a connection to each deployment target
		// fmt.Println("Adding deployment flow to:", deployTargetID)
		change.addDeployment(deployTargetID, commLinks)
	}

	techAsset := change.serverSideAsset(change.buildPipelineID, "build-pipeline", "Build Pipeline",
		types.BuildPipeline)
	techAsset.JustificationCiaRating = "Build pipeline components are at least rated as 'critical' in terms of " +
		"integrity, because any malicious modification of it might lead to a backdoored production system."
	techAsset.DataAssetsProcessed = []string{sourcecodeDataAsset, deploymentDataAsset}
	techAsset.DataAssetsStored = []string{sourcecodeDataAsset, deploymentDataAsset}
	techAsset.CommunicationLinks = commLinks
	change.addServerSideAsset(techAsset)
}

// addContainerPlatformLinks adds the links between the build pipeline, the container registry and the
// container platform: the build pipeline pushes to the platform, or the platform pulls from the registry.
func (change *buildPipelineChange) addContainerPlatformLinks(commLinks map[string]input.CommunicationLink) {
	commLinks["Container Registry Traffic"] = devOpsLink(change.containerRepoID, "Container Registry Traffic",
		types.TechnicalUser, false, []string{deploymentDataAsset}, []string{deploymentDataAsset})
	if change.answer("push-or-pull") == pushOrPull[0] { // Push
		commLinks["Container Platform Push"] = devOpsLink(change.containerPlatformID, "Container Platform Push",
			types.TechnicalUser, false, []string{deploymentDataAsset}, []string{deploymentDataAsset})
		return
	}
	// Pull
	commLinkPull := devOpsLink(change.containerRepoID, "Container Platform Pull", types.TechnicalUser, true, nil,
		[]string{deploymentDataAsset})
	if !change.dryRun {
		titleOfTargetAsset := change.answer("container-platform") + " Container Platform"
		containerPlatform := change.modelInput.TechnicalAssets[titleOfTargetAsset]
		if containerPlatform.CommunicationLinks == nil {
			containerPlatform.CommunicationLinks = make(map[string]input.CommunicationLink)
		}
		containerPlatform.CommunicationLinks["Container Platform Pull"] = commLinkPull
		change.modelInput.TechnicalAssets[titleOfTargetAsset] = containerPlatform
	}
}

// addDeployment adds the deployment of the build pipeline to a target: the container platform spawns it,
// the build pipeline pushes it, or the target pulls it from the artifact registry.
func (change *buildPipelineChange) addDeployment(deployTargetID string, commLinks map[string]input.CommunicationLink) {
	switch {
	case change.containerTechUsed:
		if !change.dryRun {
			change.addContainerSpawning(deployTargetID)
		}
	case change.answer("push-or-pull") == pushOrPull[0]: // Push
		commLinks["Deployment Push ("+deployTargetID+")"] = input.CommunicationLink{
			Target:                 deployTargetID,
			Description:            "Deployment Push to " + deployTargetID,
			Protocol:               types.SSH.String(),
			Authentication:         types.ClientCertificate.String(),
			Authorization:          types.TechnicalUser.String(),
			Tags:                   []string{},
			VPN:                    false,
			IpFiltered:             false,
			Readonly:               false,
			Usage:                  types.DevOps.String(),
			DataAssetsSent:         []string{deploymentDataAsset},
			DataAssetsReceived:     nil,
			DiagramTweakWeight:     0,
			DiagramTweakConstraint: false,
		}
	default: // Pull
		pullFromWhere := change.artifactRegistryID
		commLinkPull := devOpsLink(pullFromWhere, "Deployment Pull from "+deployTargetID, types.TechnicalUser, true,
			nil, []string{deploymentDataAsset})
		if !change.dryRun {
			// take care to lookup by title (as keyed in input YAML by title and only in parsed model representation by ID)
			titleOfTargetAsset := change.parsedModel.TechnicalAssets[deployTargetID].Title
			x := change.modelInput.TechnicalAssets[titleOfTargetAsset]
			if x.CommunicationLinks == nil {
				x.CommunicationLinks = make(map[string]input.CommunicationLink)
			}
			x.CommunicationLinks["Deployment Pull ("+deployTargetID+")"] = commLinkPull
			change.modelInput.TechnicalAssets[titleOfTargetAsset] = x
		}
	}

	// don't forget to also add the deploymentDataAsset data asset as stored on the target
	targetAssetTitle := change.parsedModel.TechnicalAssets[deployTargetID].Title
	assetsStored := change.modelInput.TechnicalAssets[targetAssetTitle].DataAssetsStored
	mergedArrays := make([]string, 0, len(assetsStored)+1)
	mergedArrays = append(mergedArrays, assetsStored...)
	mergedArrays = append(mergedArrays, deploymentDataAsset)
	if !change.dryRun {
		x := change.modelInput.TechnicalAssets[targetAssetTitle]
		x.DataAssetsStored = mergedArrays
		change.modelInput.TechnicalAssets[targetAssetTitle] = x
	}
}

func (change *buildPipelineChange) addContainerSpawning(deployTargetID string) {
	containerPlatformTitle := change.answer("container-platform") + " Container Platform"
	containerPlatform := change.modelInput.TechnicalAssets[containerPlatformTitle]
	if containerPlatform.CommunicationLinks == nil {
		containerPlatform.CommunicationLinks = make(map[string]input.CommunicationLink)
	}
	containerPlatform.CommunicationLinks["Container Spawning ("+deployTargetID+")"] = input.CommunicationLink{
		Target:                 deployTargetID,
		Description:            "Container Spawning " + deployTargetID,
		Protocol:               types.ContainerSpawning.String(),
		Authentication:         types.NoneAuthentication.String(),
		Authorization:          types.NoneAuthorization.String(),
		Tags:                   []string{},
		VPN:                    false,
		IpFiltered:             false,
		Readonly:               false,
		Usage:                  types.DevOps.String(),
		DataAssetsSent:         []string{deploymentDataAsset},
		DataAssetsReceived:     nil,
		DiagramTweakWeight:     0,
		DiagramTweakConstraint: false,
	}
	change.modelInput.TechnicalAssets[containerPlatformTitle] = containerPlatform
}

func (change *buildPipelineChange) addArtifactRegistry() {
	if change.exists(change.artifactRegistryID) {
		return
	}
	// fmt.Println("Adding technical asset:", id) // ################################################
	techAsset := change.serverSideAsset(change.artifactRegistryID, "artifact-registry", "Artifact Registry",
		types.ArtifactRegistry)
	techAsset.JustificationCiaRating = "Artifact registry components are at least rated as 'critical' in terms of " +
		"integrity, because any malicious modification of it might lead to a backdoored production system."
	techAsset.DataAssetsProcessed = []string{sourcecodeDataAsset, deploymentDataAsset}
	techAsset.DataAssetsStored = []string{sourcecodeDataAsset, deploymentDataAsset}
	change.addServerSideAsset(techAsset)
}

func (change *buildPipelineChange) addCodeInspectionPlatform() {
	if change.exists(change.codeInspectionPlatformID) {
		return
	}
	// fmt.Println("Adding technical asset:", id) // ################################################
	techAsset := change.serverSideAsset(change.codeInspectionPlatformID, types.CodeInspectionPlatform,
		"Code Inspection Platform", types.CodeInspectionPlatform)
	techAsset.Integrity = types.Important.String()
	techAsset.Availability = types.Operational.String()
	techAsset.JustificationCiaRating = "Sourcecode inspection platforms are rated at least 'important' in terms of " +
		"integrity, because any malicious modification of it might lead to vulnerabilities found by the scanner " +
		"engine not being shown."
	techAsset.DataAssetsProcessed = []string{sourcecodeDataAsset}
	techAsset.DataAssetsStored = []string{sourcecodeDataAsset}
	change.addServerSideAsset(techAsset)
}

func (change *buildPipelineChange) addToTrustBoundary() {
	if change.createNewTrustBoundary {
		trustBoundaryType := change.answer("new-trust-boundary-type")
		// fmt.Println("Adding new trust boundary of type:", trustBoundaryType)
		title := "DevOps Network"
		trustBoundary := input.TrustBoundary{
			ID:                    "devops-network",
			Description:           "DevOps Network",
			Type:                  trustBoundaryType,
			Tags:                  []string{},
			TechnicalAssetsInside: change.serverSideTechAssets,
			TrustBoundariesNested: nil,
		}
		change.logChange("adding trust boundary: devops-network")
		if !change.dryRun {
			change.modelInput.TrustBoundaries[title] = trustBoundary
		}
		return
	}

	existingTrustBoundaryToAddTo := change.answer(selectedTrustBoundaryQuestion)
	// fmt.Println("Adding to existing trust boundary:", existingTrustBoundaryToAddTo)
	title := change.parsedModel.TrustBoundaries[existingTrustBoundaryToAddTo].Title
	assetsInside := change.modelInput.TrustBoundaries[title].TechnicalAssetsInside
	mergedArrays := make([]string, 0, len(assetsInside)+len(change.serverSideTechAssets))
	mergedArrays = append(mergedArrays, assetsInside...)
	mergedArrays = append(mergedArrays, change.serverSideTechAssets...)
	change.logChange("filling existing trust boundary: " + existingTrustBoundaryToAddTo)
	if !change.dryRun {
		if change.modelInput.TrustBoundaries == nil {
			change.modelInput.TrustBoundaries = make(map[string]input.TrustBoundary)
		}
		tb := change.modelInput.TrustBoundaries[title]
		tb.TechnicalAssetsInside = mergedArrays
		change.modelInput.TrustBoundaries[title] = tb
	}
}

func (change *buildPipelineChange) addSharedRuntime() {
	// create shared runtime
	assetsRunning := make([]string, 0, len(change.macroState["deploy-targets"]))
	assetsRunning = append(assetsRunning, change.macroState["deploy-targets"]...)
	title := change.answer("container-platform") + " Runtime"
	sharedRuntime := input.SharedRuntime{
		ID:                     change.containerSharedRuntimeID,
		Description:            title,
		Tags:                   []string{input.NormalizeTag(change.answer("container-platform"))},
		TechnicalAssetsRunning: assetsRunning,
	}
	change.logChange("adding shared runtime: " + change.containerSharedRuntimeID)
	if !change.dryRun {
		if change.modelInput.SharedRuntimes == nil {
			change.modelInput.SharedRuntimes = make(map[string]input.SharedRuntime)
		}
		change.modelInput.SharedRuntimes[title] = sharedRuntime
	}
}
