package macros

import (
	"slices"
	"strings"

	"github.com/Pinguladora/threagile/pkg/input"
	"github.com/Pinguladora/threagile/pkg/types"
)

type AddVaultMacro struct {
	macroState             map[string][]string
	questionsAnswered      []string
	withinTrustBoundary    bool
	createNewTrustBoundary bool
}

const createNewTrustBoundaryLabel = "CREATE NEW TRUST BOUNDARY"

var storageTypes = []string{
	"Cloud Provider (storage buckets or similar)",
	"Container Platform (orchestration platform managed storage)",
	// the macro does not offer to reuse an existing technical asset as shared storage (which would be bad)
	"Database (SQL-DB, NoSQL-DB, object store or similar)",
	"Filesystem (local or remote)",
	"In-Memory (no persistent storage of secrets)",
	// the macro does not ask which technical asset the registry is (for the comm link)
	"Service Registry",
}

var authenticationTypes = []string{
	"Certificate",
	"Cloud Provider (relying on cloud provider instance authentication)",
	"Container Platform (orchestration platform managed authentication)",
	"Credentials (username/password, API-key, secret token, etc.)",
}

func NewAddVault() *AddVaultMacro {
	return &AddVaultMacro{
		macroState:        make(map[string][]string),
		questionsAnswered: make([]string, 0),
	}
}

func (m *AddVaultMacro) GetMacroDetails() MacroDetails {
	return MacroDetails{
		ID:          "add-vault",
		Title:       "Add Vault",
		Description: "This model macro adds a vault (secret storage) to the model.",
	}
}

// The questions of the vault macro by their number; questions 4 and 6 depend on the model.
var vaultQuestions = map[int]MacroQuestion{
	0: {
		ID:              "vault-name",
		Title:           "What product is used as the vault?",
		Description:     productNameDescription,
		PossibleAnswers: nil,
		MultiSelect:     false,
		DefaultAnswer:   "",
	},
	1: {
		ID:              "storage-type",
		Title:           "What type of storage is used for the vault?",
		Description:     "This selection affects the type of technical asset for the persistence.",
		PossibleAnswers: storageTypes,
		MultiSelect:     false,
		DefaultAnswer:   "",
	},
	2: {
		ID:              "authentication-type",
		Title:           "What type of authentication is used for accessing the vault?",
		Description:     "This selection affects the type of communication links.",
		PossibleAnswers: authenticationTypes,
		MultiSelect:     false,
		DefaultAnswer:   "",
	},
	3: {
		ID:              "multi-tenant",
		Title:           "Is the vault used by multiple tenants?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerNo,
	},
	5: {
		ID:              withinTrustBoundaryQuestion,
		Title:           "Is the vault placed within a network trust boundary?",
		Description:     "",
		PossibleAnswers: []string{answerYes, answerNo},
		MultiSelect:     false,
		DefaultAnswer:   answerYes,
	},
	7: newTrustBoundaryTypeQuestion,
}

// The numbers of the questions of the vault macro that depend on the model.
const (
	clientsQuestionNumber                  = 4
	selectVaultTrustBoundaryQuestionNumber = 6
)

func (m *AddVaultMacro) GetNextQuestion(parsedModel *types.Model) (nextQuestion MacroQuestion, err error) {
	counter := len(m.questionsAnswered)
	if counter > 5 && !m.withinTrustBoundary {
		counter++
	}
	if counter > 6 && !m.createNewTrustBoundary {
		counter++
	}
	switch counter {
	case clientsQuestionNumber:
		return technicalAssetsQuestion(parsedModel, "clients",
			"Select all technical assets that make use of the vault and access it:"), nil
	case selectVaultTrustBoundaryQuestionNumber:
		return selectTrustBoundaryQuestion(parsedModel), nil
	}
	if question, ok := vaultQuestions[counter]; ok {
		return question, nil
	}
	return NoMoreQuestions(), nil
}

func (m *AddVaultMacro) ApplyAnswer(questionID string, answer ...string) (message string, validResult bool, err error) {
	m.macroState[questionID] = answer
	m.questionsAnswered = append(m.questionsAnswered, questionID)
	switch questionID {
	case withinTrustBoundaryQuestion:
		m.withinTrustBoundary = strings.EqualFold(m.macroState[withinTrustBoundaryQuestion][0], "yes")

	case selectedTrustBoundaryQuestion:
		m.createNewTrustBoundary = strings.EqualFold(m.macroState[selectedTrustBoundaryQuestion][0],
			createNewTrustBoundaryLabel)
	}

	return answerProcessed, true, nil
}

func (m *AddVaultMacro) GoBack() (message string, validResult bool, err error) {
	if len(m.questionsAnswered) == 0 {
		return cannotGoBackFurther, false, nil
	}
	lastQuestionID := m.questionsAnswered[len(m.questionsAnswered)-1]
	m.questionsAnswered = m.questionsAnswered[:len(m.questionsAnswered)-1]
	delete(m.macroState, lastQuestionID)
	return "Undo successful", true, nil
}

func (m *AddVaultMacro) GetFinalChangeImpact(
	modelInput *input.Model, parsedModel *types.Model,
) (changes []string, message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult = m.applyChange(modelInput, parsedModel, &changeLogCollector, true)
	return changeLogCollector, message, validResult, nil
}

func (m *AddVaultMacro) Execute(
	modelInput *input.Model, parsedModel *types.Model,
) (message string, validResult bool, err error) {
	changeLogCollector := make([]string, 0)
	message, validResult = m.applyChange(modelInput, parsedModel, &changeLogCollector, false)
	return message, validResult, nil
}

// vaultChange applies the answers of the vault macro to a model, or for a dry run only collects the
// changes it would make.
type vaultChange struct {
	*AddVaultMacro
	modelInput         *input.Model
	parsedModel        *types.Model
	changeLogCollector *[]string
	dryRun             bool

	databaseUsed, filesystemUsed, inMemoryUsed bool
	storageID, vaultID, vaultEnvID             string

	// the server-side technical assets the macro adds, which it places in a trust boundary
	serverSideTechAssets []string
}

func (m *AddVaultMacro) applyChange(
	modelInput *input.Model, parsedModel *types.Model, changeLogCollector *[]string, dryRun bool,
) (message string, validResult bool) {
	modelInput.AddTagToModelInput(m.macroState["vault-name"][0], dryRun, changeLogCollector)

	change := &vaultChange{
		AddVaultMacro:        m,
		modelInput:           modelInput,
		parsedModel:          parsedModel,
		changeLogCollector:   changeLogCollector,
		dryRun:               dryRun,
		serverSideTechAssets: make([]string, 0),
	}

	change.addConfigurationSecrets()

	change.databaseUsed = m.macroState["storage-type"][0] == storageTypes[2]
	change.filesystemUsed = m.macroState["storage-type"][0] == storageTypes[3]
	change.inMemoryUsed = m.macroState["storage-type"][0] == storageTypes[4]

	change.storageID = "vault-storage"

	if change.databaseUsed || change.filesystemUsed {
		change.addStorage()
	}

	change.vaultID = types.MakeID(m.macroState["vault-name"][0]) + "-vault"

	if _, exists := parsedModel.TechnicalAssets[change.vaultID]; !exists {
		change.addVault()
	}

	change.vaultEnvID = "vault-environment"
	if change.filesystemUsed {
		change.addVaultEnvironment()
	}

	if m.withinTrustBoundary {
		if m.createNewTrustBoundary {
			change.addVaultNetwork()
		} else { // adding to existing trust boundary
			change.addToExistingTrustBoundary()
		}
	}

	return changesetValid, true
}

func (change *vaultChange) logChange(text string) {
	*change.changeLogCollector = append(*change.changeLogCollector, text)
}

func (change *vaultChange) addConfigurationSecrets() {
	if _, exists := change.parsedModel.DataAssets[configurationSecretsDataAsset]; exists {
		return
	}
	dataAsset := input.DataAsset{
		ID: configurationSecretsDataAsset,
		Description: "Configuration secrets (like credentials, keys, certificates, etc.) secured and managed " +
			"by a vault",
		Usage:                  types.DevOps.String(),
		Tags:                   []string{},
		Origin:                 "",
		Owner:                  "",
		Quantity:               types.VeryFew.String(),
		Confidentiality:        types.StrictlyConfidential.String(),
		Integrity:              types.Critical.String(),
		Availability:           types.Critical.String(),
		JustificationCiaRating: "Configuration secrets are rated as being 'strictly-confidential'.",
	}
	change.logChange("adding data asset: configuration-secrets")
	if !change.dryRun {
		change.modelInput.DataAssets["Configuration Secrets"] = dataAsset
	}
}

func (change *vaultChange) addStorage() {
	// the macro does not ask whether the filesystem is local or remote; only a local one would call for
	// the execution-environment (and maybe a separate tech type LocalFilesystem)
	tech := types.FileServer
	if change.databaseUsed {
		tech = types.Database
	}
	if _, exists := change.parsedModel.TechnicalAssets[change.storageID]; exists {
		return
	}
	change.serverSideTechAssets = append(change.serverSideTechAssets, change.storageID)
	techAsset := input.TechnicalAsset{
		ID:                      change.storageID,
		Description:             "Vault Storage",
		Type:                    types.Datastore.String(),
		Usage:                   types.DevOps.String(),
		UsedAsClientByHuman:     false,
		OutOfScope:              false,
		JustificationOutOfScope: "",
		Size:                    types.Component.String(),
		Technology:              tech,
		Tags:                    []string{}, // not asked for: maybe too detailed for a wizard
		Internet:                false,
		Machine:                 types.Virtual.String(), // not asked for: maybe too detailed for a wizard
		// can be assumed for a vault product as at least having some good encryption
		Encryption:      types.DataWithSymmetricSharedKey.String(),
		Owner:           "",
		Confidentiality: types.Confidential.String(),
		Integrity:       types.Critical.String(),
		Availability:    types.Critical.String(),
		JustificationCiaRating: "Vault components are only rated as 'confidential' as vaults usually apply a trust " +
			"barrier to encrypt all data-at-rest with a vault key.",
		MultiTenant:          strings.EqualFold(change.macroState["multi-tenant"][0], "yes"),
		Redundant:            false,
		CustomDevelopedParts: false,
		DataAssetsProcessed:  nil,
		DataAssetsStored:     []string{configurationSecretsDataAsset},
		DataFormatsAccepted:  nil,
		CommunicationLinks:   nil,
	}
	change.logChange("adding technical asset: " + change.storageID)
	if !change.dryRun {
		change.modelInput.TechnicalAssets["Vault Storage"] = techAsset
	}
}

func (change *vaultChange) addVault() {
	change.serverSideTechAssets = append(change.serverSideTechAssets, change.vaultID)
	commLinks := make(map[string]input.CommunicationLink)

	if change.databaseUsed || change.filesystemUsed {
		commLinks["Vault Storage Access"] = change.storageAccessLink()
	}

	authentication := change.authentication()
	for _, clientID := range change.macroState["clients"] { // add a connection from each client
		change.addClientAccess(clientID, authentication)
	}

	techAsset := input.TechnicalAsset{
		ID:                      change.vaultID,
		Description:             change.macroState["vault-name"][0] + " Vault",
		Type:                    types.Process.String(),
		Usage:                   types.DevOps.String(),
		UsedAsClientByHuman:     false,
		OutOfScope:              false,
		JustificationOutOfScope: "",
		Size:                    types.Service.String(),
		Technology:              types.Vault,
		Tags:                    []string{input.NormalizeTag(change.macroState["vault-name"][0])},
		Internet:                false,
		Machine:                 types.Virtual.String(),
		Encryption:              types.Transparent.String(),
		Owner:                   "",
		Confidentiality:         types.StrictlyConfidential.String(),
		Integrity:               types.Critical.String(),
		Availability:            types.Critical.String(),
		JustificationCiaRating:  "Vault components are rated as 'strictly-confidential'.",
		MultiTenant:             strings.EqualFold(change.macroState["multi-tenant"][0], "yes"),
		Redundant:               false,
		CustomDevelopedParts:    false,
		DataAssetsProcessed:     []string{configurationSecretsDataAsset},
		DataAssetsStored:        nil,
		DataFormatsAccepted:     nil,
		CommunicationLinks:      commLinks,
	}
	if change.inMemoryUsed {
		techAsset.DataAssetsStored = []string{configurationSecretsDataAsset}
	}
	change.logChange("adding technical asset (including communication links): " + change.vaultID)
	if !change.dryRun {
		change.modelInput.TechnicalAssets[change.macroState["vault-name"][0]+" Vault"] = techAsset
	}
}

// storageAccessLink is the link of the vault to its storage.
func (change *vaultChange) storageAccessLink() input.CommunicationLink {
	accessLink := input.CommunicationLink{
		Target:                 change.storageID,
		Description:            "Vault Storage Access",
		Protocol:               types.LocalFileAccess.String(),
		Authentication:         types.Credentials.String(),
		Authorization:          types.TechnicalUser.String(),
		Tags:                   []string{},
		VPN:                    false,
		IpFiltered:             false,
		Readonly:               false,
		Usage:                  types.DevOps.String(),
		DataAssetsSent:         []string{configurationSecretsDataAsset},
		DataAssetsReceived:     []string{configurationSecretsDataAsset},
		DiagramTweakWeight:     0,
		DiagramTweakConstraint: false,
	}
	if change.databaseUsed {
		// not asked whether it is encrypted or NoSQL: maybe too detailed for a wizard
		accessLink.Protocol = types.SqlAccessProtocol.String()
	}
	return accessLink
}

// authentication is how the clients authenticate at the vault.
func (change *vaultChange) authentication() string {
	switch change.macroState["authentication-type"][0] {
	case authenticationTypes[0]:
		return types.ClientCertificate.String()
	case authenticationTypes[1]:
		return types.Externalized.String()
	case authenticationTypes[2]:
		return types.Externalized.String()
	case authenticationTypes[3]:
		return types.Credentials.String()
	}
	return types.NoneAuthentication.String()
}

// addClientAccess adds the link of a client to the vault, and the configuration secrets to the data assets
// that the client processes.
func (change *vaultChange) addClientAccess(clientID string, authentication string) {
	clientAccessCommLink := input.CommunicationLink{
		Target:                 change.vaultID,
		Description:            "Vault Access Traffic (by " + clientID + ")",
		Protocol:               types.HTTPS.String(),
		Authentication:         authentication,
		Authorization:          types.TechnicalUser.String(),
		Tags:                   []string{},
		VPN:                    false,
		IpFiltered:             false,
		Readonly:               true,
		Usage:                  types.DevOps.String(),
		DataAssetsSent:         nil,
		DataAssetsReceived:     []string{configurationSecretsDataAsset},
		DiagramTweakWeight:     0,
		DiagramTweakConstraint: false,
	}
	clientAssetTitle := change.parsedModel.TechnicalAssets[clientID].Title
	if !change.dryRun {
		client := change.modelInput.TechnicalAssets[clientAssetTitle]
		if client.CommunicationLinks == nil {
			client.CommunicationLinks = make(map[string]input.CommunicationLink)
		}
		client.CommunicationLinks["Vault Access ("+clientID+")"] = clientAccessCommLink
		change.modelInput.TechnicalAssets[clientAssetTitle] = client
	}
	// don't forget to also add the "configuration-secrets" data asset as processed on the client
	assetsProcessed := change.modelInput.TechnicalAssets[clientAssetTitle].DataAssetsProcessed
	if slices.Contains(assetsProcessed, configurationSecretsDataAsset) {
		return
	}
	mergedArrays := make([]string, 0, len(assetsProcessed)+1)
	mergedArrays = append(mergedArrays, assetsProcessed...)
	mergedArrays = append(mergedArrays, configurationSecretsDataAsset)
	if !change.dryRun {
		x := change.modelInput.TechnicalAssets[clientAssetTitle]
		x.DataAssetsProcessed = mergedArrays
		change.modelInput.TechnicalAssets[clientAssetTitle] = x
	}
}

func (change *vaultChange) addVaultEnvironment() {
	title := "Vault Environment"
	trustBoundary := input.TrustBoundary{
		ID:                    change.vaultEnvID,
		Description:           "Vault Environment",
		Type:                  types.ExecutionEnvironment.String(),
		Tags:                  []string{},
		TechnicalAssetsInside: []string{change.vaultID, change.storageID},
		TrustBoundariesNested: nil,
	}
	change.logChange("adding trust boundary: " + change.vaultEnvID)
	if !change.dryRun {
		change.modelInput.TrustBoundaries[title] = trustBoundary
	}
}

func (change *vaultChange) addVaultNetwork() {
	trustBoundaryType := change.macroState["new-trust-boundary-type"][0]
	title := "Vault Network"
	trustBoundary := input.TrustBoundary{
		ID:          "vault-network",
		Description: "Vault Network",
		Type:        trustBoundaryType,
		Tags:        []string{},
	}
	if change.filesystemUsed {
		trustBoundary.TrustBoundariesNested = []string{change.vaultEnvID}
	} else {
		trustBoundary.TechnicalAssetsInside = change.serverSideTechAssets
	}
	change.logChange("adding trust boundary: vault-network")
	if !change.dryRun {
		change.modelInput.TrustBoundaries[title] = trustBoundary
	}
}

func (change *vaultChange) addToExistingTrustBoundary() {
	existingTrustBoundaryToAddTo := change.macroState[selectedTrustBoundaryQuestion][0]
	title := change.parsedModel.TrustBoundaries[existingTrustBoundaryToAddTo].Title

	if change.filesystemUsed { // ------------------ nest as execution-environment trust boundary ------------------
		boundariesNested := change.modelInput.TrustBoundaries[title].TrustBoundariesNested
		mergedArrays := make([]string, 0, len(boundariesNested)+1)
		mergedArrays = append(mergedArrays, boundariesNested...)
		mergedArrays = append(mergedArrays, change.vaultEnvID)
		change.logChange("filling existing trust boundary: " + existingTrustBoundaryToAddTo)
		if !change.dryRun {
			tb := change.modelInput.TrustBoundaries[title]
			tb.TrustBoundariesNested = mergedArrays
			change.modelInput.TrustBoundaries[title] = tb
		}
		return
	}

	// ---------------------- place assets inside directly ----------------------
	assetsInside := change.modelInput.TrustBoundaries[title].TechnicalAssetsInside
	mergedArrays := make([]string, 0, len(assetsInside)+len(change.serverSideTechAssets))
	mergedArrays = append(mergedArrays, assetsInside...)
	mergedArrays = append(mergedArrays, change.serverSideTechAssets...)
	change.logChange("filling existing trust boundary: " + existingTrustBoundaryToAddTo)
	if !change.dryRun {
		tb := change.modelInput.TrustBoundaries[title]
		tb.TechnicalAssetsInside = mergedArrays
		change.modelInput.TrustBoundaries[title] = tb
	}
}
