package risks

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"

	"github.com/Pinguladora/threagile/pkg/risks/builtin"
	"github.com/Pinguladora/threagile/pkg/risks/script"
	"github.com/Pinguladora/threagile/pkg/types"
)

func GetBuiltInRiskRules() types.RiskRules {
	rules := make(types.RiskRules)
	for _, rule := range builtInRiskRules() {
		rules[rule.Category().ID] = rule
	}

	scriptRules, scriptError := GetScriptRiskRules()
	if scriptError != nil {
		fmt.Printf("error loading script risk rules: %v\n", scriptError)
		return rules
	}

	for id, rule := range scriptRules {
		// the embedded scripts include ports of built-in rules that exercise the script engine: the built-in rule
		// of an id is the one that runs, with its references and its explanations
		if _, isBuiltIn := rules[id]; isBuiltIn {
			continue
		}

		rules[id] = rule
	}

	return rules
}

func builtInRiskRules() []types.RiskRule {
	return slices.Concat(coreRiskRules(), aiRiskRules(), otRiskRules(), accessRiskRules(), kubernetesRiskRules())
}

// aiRiskRules are the rules of systems built on language models and agents.
func aiRiskRules() []types.RiskRule {
	return []types.RiskRule{
		builtin.NewConfusedDeputyAgentRule(),
		builtin.NewExcessiveAgencyRule(),
		builtin.NewInsecureInterAgentCommunicationRule(),
		builtin.NewMissingAIGuardrailRule(),
		builtin.NewMissingAIMonitoringRule(),
		builtin.NewModelOutputDisclosureRule(),
		builtin.NewModelSupplyChainRule(),
		builtin.NewPromptInjectionRule(),
		builtin.NewUnauthenticatedMCPServerRule(),
		builtin.NewUnboundedModelConsumptionRule(),
		builtin.NewUnsandboxedCodeExecutionRule(),
		builtin.NewVectorStorePoisoningRule(),
	}
}

// otRiskRules are the rules of industrial control systems.
func otRiskRules() []types.RiskRule {
	return []types.RiskRule{
		builtin.NewDirectITOTCommunicationRule(),
		builtin.NewInsecureControlProtocolRule(),
		builtin.NewMissingSafetySystemIndependenceRule(),
	}
}

// accessRiskRules are the rules on the credentials, identities and authorization of communication links.
func accessRiskRules() []types.RiskRule {
	return []types.RiskRule{
		builtin.NewHumanUseOfMachineIdentityRule(),
		builtin.NewLongLivedCredentialsRule(),
		builtin.NewMissingObjectLevelAuthorizationRule(),
		builtin.NewMissingPolicyDecisionPointRedundancyRule(),
		builtin.NewOverprivilegedMachineIdentityRule(),
		builtin.NewSharedMachineAccountRule(),
		builtin.NewUnprotectedAuthorizationDecisionsRule(),
	}
}

// coreRiskRules are the rules of every model.
func coreRiskRules() []types.RiskRule {
	return []types.RiskRule{
		builtin.NewAccidentalSecretLeakRule(),
		builtin.NewCodeBackdooringRule(),
		builtin.NewContainerBaseImageBackdooringRule(),
		builtin.NewContainerPlatformEscapeRule(),
		builtin.NewCrossAccountTakeoverRule(),
		builtin.NewCrossSiteRequestForgeryRule(),
		builtin.NewCrossSiteScriptingRule(),
		builtin.NewDosRiskyAccessAcrossTrustBoundaryRule(),
		builtin.NewEncryptionKeyDeletionRule(),
		builtin.NewIncompleteModelRule(),
		builtin.NewLdapInjectionRule(),
		builtin.NewMissingAuthenticationRule(),
		builtin.NewMissingAuthenticationSecondFactorRule(builtin.NewMissingAuthenticationRule()),
		builtin.NewMissingBuildInfrastructureRule(),
		builtin.NewMissingCloudHardeningRule(),
		builtin.NewMissingFileValidationRule(),
		builtin.NewMissingHardeningRule(),
		builtin.NewMissingIdentityPropagationRule(),
		builtin.NewMissingIdentityProviderIsolationRule(),
		builtin.NewMissingIdentityStoreRule(),
		builtin.NewMissingNetworkSegmentationRule(),
		builtin.NewMissingVaultRule(),
		builtin.NewMissingVaultIsolationRule(),
		builtin.NewMissingWafRule(),
		builtin.NewMixedTargetsOnSharedRuntimeRule(),
		builtin.NewPathTraversalRule(),
		builtin.NewPublicCloudAssetAccessRule(),
		builtin.NewPublicCloudSnapshotRule(),
		builtin.NewPushInsteadPullDeploymentRule(),
		builtin.NewSearchQueryInjectionRule(),
		builtin.NewServerSideRequestForgeryRule(),
		builtin.NewServiceRegistryPoisoningRule(),
		builtin.NewSqlNoSqlInjectionRule(),
		builtin.NewUncheckedDeploymentRule(),
		builtin.NewUnencryptedAssetRule(),
		builtin.NewUnencryptedCommunicationRule(),
		builtin.NewUnguardedAccessFromInternetRule(),
		builtin.NewUnguardedDirectDatastoreAccessRule(),
		builtin.NewUnnecessaryCommunicationLinkRule(),
		builtin.NewUnnecessaryDataAssetRule(),
		builtin.NewUnnecessaryDataTransferRule(),
		builtin.NewUnnecessaryTechnicalAssetRule(),
		builtin.NewUntrustedDeserializationRule(),
		builtin.NewWrongCommunicationLinkContentRule(),
		builtin.NewWrongTrustBoundaryContentRule(),
		builtin.NewXmlExternalEntityRule(),
	}
}

//go:embed scripts/*.yaml
var ruleScripts embed.FS

type RiskRules types.RiskRules

func GetScriptRiskRules() (RiskRules, error) {
	return make(RiskRules).LoadRiskRules()
}

func (what RiskRules) LoadRiskRules() (RiskRules, error) {
	fileSystem := ruleScripts
	walkError := fs.WalkDir(fileSystem, "scripts", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		newRule := new(script.RiskRule).Init()
		loadError := newRule.Load(fileSystem, path, entry)
		if loadError != nil {
			return fmt.Errorf("error loading risk rule script %q: %w", path, loadError)
		}

		if newRule.Category().ID == "" {
			return nil
		}

		what[newRule.Category().ID] = newRule
		return nil
	})

	if walkError != nil {
		return nil, walkError //nolint:wrapcheck // WalkDir passes on the errors of the walk function, which wraps them
	}

	return what, nil
}

// kubernetesRiskRules are the rules of workloads in Kubernetes clusters.
func kubernetesRiskRules() []types.RiskRule {
	return []types.RiskRule{
		builtin.NewKubernetesAPIWriteAccessRule(),
		builtin.NewMissingNetworkPolicyRule(),
		builtin.NewPrivilegedWorkloadRule(),
	}
}
