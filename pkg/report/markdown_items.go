package report

import (
	"strconv"
	"strings"
)

// itemLine is the line below the heading of an object: its level, if any, its summary and its id.
func itemLine(level *viewLevel, summary string, id string) string {
	parts := make([]string, 0, 3)
	if level != nil {
		parts = append(parts, strong(level.Title))
	}
	if summary != "" {
		parts = append(parts, markdownText(summary))
	}
	if id != "" {
		parts = append(parts, markdownCode(id))
	}
	return strings.Join(parts, " · ")
}

// labelled writes markup text below its label, as the HTML report writes it below a heading.
func (what *markdownWriter) labelled(label string, text markupText) {
	what.subheading(label)
	what.markup(text)
}

// subheading is the heading of a part of an item, below the item's own heading, as the HTML report has it.
func (what *markdownWriter) subheading(title string) {
	what.heading(4, "", title)
}

func (what *markdownWriter) riskCategories(view *reportView) {
	what.paragraph("In total " + strong(plural(view.Summary.TotalRisks, "potential risk", "potential risks")) +
		" have been identified during the threat modeling process, distributed across " +
		strong(plural(view.Summary.CategoryCount, "vulnerability category", "vulnerability categories")) +
		". The following sections describe each identified risk category and its risks.")
	for index := range view.Categories {
		what.riskCategory(&view.Categories[index])
	}
}

func (what *markdownWriter) riskCategory(category *viewCategory) {
	slug := what.heading(3, category.Anchor, category.Category.Title)
	for _, risk := range category.Risks {
		what.alias(risk.Anchor, slug) // a risk has no heading of its own
	}
	what.paragraph(itemLine(category.Severity, category.Summary, category.Category.ID))

	what.properties(categoryProperties(category)...)
	what.labelled("Description", category.Description)
	what.labelled("Impact", category.Impact)
	what.labelled("Detection Logic", category.DetectionLogic)
	what.labelled("Risk Rating", category.RiskAssessment)
	what.labelled("False Positives", category.FalsePositives)
	what.labelled("Mitigation", category.Mitigation)
	what.labelled("Check", category.Check)

	what.subheading("Risk Findings")
	what.paragraph("The risk " + strong(markdownText(category.Category.Title)) + " was found " +
		strong(plural(len(category.Risks), "time", "times")) + " in the analyzed architecture to be potentially " +
		"possible. Each spot should be checked individually by reviewing the implementation whether all controls " +
		"have been applied properly in order to mitigate each risk.")
	rows := make([][]string, 0, len(category.Risks))
	for _, risk := range category.Risks {
		rows = append(rows, []string{
			risk.Severity.Title, markdownInline(risk.Title), markdownCode(risk.SyntheticID),
			markdownText(risk.Likelihood), markdownText(risk.Impact), what.refs(risk.Targets), risk.Status.Title,
			trackingCell(risk),
		})
	}
	what.table([]markdownColumn{
		{columnSeverity, false},
		{textRisk, false},
		{"ID", false},
		{"Likelihood", false},
		{"Impact", false},
		{"Most relevant", false},
		{columnStatus, false},
		{"Tracking", false},
	}, rows...)
}

// categoryProperties are the rows of the property table of a risk category.
func categoryProperties(category *viewCategory) [][]string {
	cwe, asvs, cheatSheet := textNotApplicable, markdownText(category.Category.ASVS), textNotApplicable
	if category.CWELink != "" {
		cwe = markdownLink("CWE "+strconv.Itoa(category.Category.CWE), markdownURL(category.CWELink))
	}
	if asvs == "" {
		asvs = textNotApplicable
	}
	if category.CheatSheet.Anchor != "" {
		cheatSheet = markdownLink(markdownText(category.CheatSheet.Title), markdownURL(category.CheatSheet.Anchor))
	}
	properties := [][]string{
		{columnSTRIDE, markdownText(category.Category.STRIDE.Title())},
		{"CWE", cwe},
		{"Function", markdownText(category.Category.Function.Title())},
		{"Action", markdownText(category.Category.Action)},
		{"ASVS chapter", asvs},
		{"Cheat sheet", cheatSheet},
	}
	if len(category.Category.References) > 0 {
		references := make([]string, 0, len(category.Category.References))
		for _, reference := range category.Category.References {
			references = append(references, markdownText(reference))
		}
		properties = append(properties, []string{"References", strings.Join(references, "; ")})
	}
	return properties
}

func (what *markdownWriter) technicalAssets(view *reportView) {
	what.paragraph("In total " + strong(plural(view.Summary.TotalRisks, "potential risk", "potential risks")) +
		" have been identified during the threat modeling process, distributed across " +
		strong(plural(len(view.Model.InScopeTechnicalAssets()), "in-scope technical asset", "in-scope technical assets")) +
		". The RAA value of a technical asset is the calculated \"Relative Attacker Attractiveness\" value in percent.")
	for index := range view.TechnicalAssets {
		what.technicalAsset(&view.TechnicalAssets[index])
	}
}

func (what *markdownWriter) technicalAsset(asset *viewTechnicalAsset) {
	what.heading(3, asset.Anchor, asset.Asset.Title)
	if asset.Asset.OutOfScope {
		what.paragraph(itemLine(&viewLevel{Title: viewOutOfScopeText}, "", asset.Asset.Id))
	} else {
		what.paragraph(itemLine(asset.Severity, asset.Summary, asset.Asset.Id))
	}
	what.markup(asset.Description)

	what.subheading("Identified Risks of the Asset")
	switch {
	case len(asset.Risks) > 0:
		what.list(what.riskItems(asset.Risks, false)...)
	case asset.Asset.OutOfScope:
		what.paragraph(muted("The asset was defined as out-of-scope."))
	default:
		what.paragraph(muted("No risks were identified."))
	}

	trustBoundary := viewNone
	if asset.TrustBoundary != nil {
		trustBoundary = what.ref(*asset.TrustBoundary)
	}
	what.subheading("Asset Information")
	what.properties(
		[]string{"Type", markdownText(asset.Asset.Type.String())},
		[]string{columnUsage, markdownText(asset.Asset.Usage.String())},
		[]string{"RAA", markdownText(asset.RAA)},
		[]string{"Size", markdownText(asset.Asset.Size.String())},
		[]string{"Technology", markdownText(asset.Asset.Technologies.String())},
		[]string{columnTags, markdownText(asset.Tags)},
		[]string{"Trust boundary", trustBoundary},
		[]string{"Internet", yesNo(asset.Asset.Internet)},
		[]string{"Machine", markdownText(asset.Asset.Machine.String())},
		[]string{"Encryption", markdownText(asset.Asset.Encryption.String())},
		[]string{"Multi-tenant", yesNo(asset.Asset.MultiTenant)},
		[]string{"Redundant", yesNo(asset.Asset.Redundant)},
		[]string{"Custom-developed", yesNo(asset.Asset.CustomDevelopedParts)},
		[]string{"Client used by a human", yesNo(asset.Asset.UsedAsClientByHuman)},
		[]string{"Data formats accepted", markdownText(asset.FormatsAccepted)},
		[]string{"Data processed", what.refs(asset.DataProcessed)},
		[]string{"Data stored", what.refs(asset.DataStored)},
		[]string{"Outgoing communication links", what.refs(asset.Outgoing)},
		[]string{"Incoming communication links", what.refs(asset.Incoming)},
	)
	rating := [][]string{
		{"Owner", markdownText(asset.Asset.Owner)},
		{"Confidentiality", markdownText(asset.Asset.Confidentiality.String())},
		{"Integrity", markdownText(asset.Asset.Integrity.String())},
		{"Availability", markdownText(asset.Asset.Availability.String())},
		{"CIA justification", markdownInline(asset.Justification)},
	}
	if asset.Asset.OutOfScope {
		rating = append(rating, []string{"Out-of-scope justification", markdownInline(asset.OutOfScope)})
	}
	what.subheading("Asset Rating")
	what.properties(rating...)
}

// riskItems are risks with their severity and status, each linked to its details, and with its
// data breach probability first if asked for.
func (what *markdownWriter) riskItems(risks []*viewRisk, dataBreach bool) []string {
	items := make([]string, 0, len(risks))
	for _, risk := range risks {
		item := strong(risk.Severity.Title) + ": " + what.riskLink(risk) + " (" + risk.Status.Title + ")"
		if dataBreach {
			item = markdownText(risk.DataBreachProbability) + ", " + item
		}
		items = append(items, item)
	}
	return items
}

func (what *markdownWriter) dataAssets(view *reportView) {
	what.paragraph("In total " + strong(plural(view.Summary.TotalRisks, "potential risk", "potential risks")) +
		" have been identified during the threat modeling process, distributed across " +
		strong(plural(len(view.DataAssets), "data asset", "data assets")) +
		". The following sections describe the derived data breach probabilities grouped by data asset.")
	for index := range view.DataAssets {
		what.dataAsset(&view.DataAssets[index])
	}
}

func (what *markdownWriter) dataAsset(asset *viewDataAsset) {
	what.heading(3, asset.Anchor, asset.Asset.Title)
	what.paragraph(itemLine(asset.Breach, asset.Summary, asset.Asset.Id))
	what.markup(asset.Description)
	breach := viewNone
	if asset.Breach != nil {
		breach = asset.Breach.Title
	}
	what.properties(
		[]string{columnUsage, markdownText(asset.Asset.Usage.String())},
		[]string{"Quantity", markdownText(asset.Asset.Quantity.String())},
		[]string{columnTags, markdownText(asset.Tags)},
		[]string{"Origin", markdownText(asset.Asset.Origin)},
		[]string{"Owner", markdownText(asset.Asset.Owner)},
		[]string{"Confidentiality", markdownText(asset.Asset.Confidentiality.String())},
		[]string{"Integrity", markdownText(asset.Asset.Integrity.String())},
		[]string{"Availability", markdownText(asset.Asset.Availability.String())},
		[]string{"CIA justification", markdownInline(asset.Justification)},
		[]string{"Processed by", what.refs(asset.ProcessedBy)},
		[]string{"Stored by", what.refs(asset.StoredBy)},
		[]string{"Sent via", what.refs(asset.SentVia)},
		[]string{"Received via", what.refs(asset.ReceivedVia)},
		[]string{"Data breach", breach},
	)
	what.subheading("Data Breach Risks")
	if len(asset.BreachRisks) == 0 {
		what.paragraph(muted("This data asset has no data breach potential."))
		return
	}
	what.paragraph("This data asset has data breach potential because of " +
		plural(len(asset.BreachRisks), "remaining risk", "remaining risks") + ":")
	what.list(what.riskItems(asset.BreachRisks, true)...)
}

func (what *markdownWriter) trustBoundaries(view *reportView) {
	what.paragraph("In total " + strong(plural(len(view.TrustBoundaries), "trust boundary has", "trust boundaries have")) +
		" been modeled during the threat modeling process.")
	for _, boundary := range view.TrustBoundaries {
		what.heading(3, boundary.Anchor, boundary.Boundary.Title)
		what.paragraph(markdownCode(boundary.Boundary.Id))
		what.markup(boundary.Description)
		boundaryType := markdownText(boundary.Boundary.Type.String())
		if !boundary.Boundary.Type.IsNetworkBoundary() {
			boundaryType += " (not a network boundary)"
		}
		parent := viewNone
		if boundary.Parent != nil {
			parent = what.ref(*boundary.Parent)
		}
		what.properties(
			[]string{"Type", boundaryType},
			[]string{columnTags, markdownText(boundary.Tags)},
			[]string{"Nested in", parent},
			[]string{"Assets inside", what.refs(boundary.AssetsInside)},
			[]string{"Boundaries nested", what.refs(boundary.Nested)},
		)
	}
}

func (what *markdownWriter) sharedRuntimes(view *reportView) {
	what.paragraph("In total " + strong(plural(len(view.SharedRuntimes), "shared runtime has", "shared runtimes have")) +
		" been modeled during the threat modeling process.")
	for _, runtime := range view.SharedRuntimes {
		what.heading(3, runtime.Anchor, runtime.Runtime.Title)
		what.paragraph(markdownCode(runtime.Runtime.Id))
		what.markup(runtime.Description)
		what.properties(
			[]string{columnTags, markdownText(runtime.Tags)},
			[]string{"Assets running", what.refs(runtime.AssetsRunning)},
		)
	}
}

func (what *markdownWriter) communicationLinks(view *reportView) {
	what.paragraph("In total " + strong(plural(len(view.CommunicationLinks), "communication link has",
		"communication links have")) + " been modeled, listed by their source asset.")
	for _, link := range view.CommunicationLinks {
		what.heading(3, link.Anchor, link.Link.Title)
		what.paragraph("from " + what.ref(link.Source) + " to " + what.ref(link.Target) + " · " +
			markdownCode(link.Link.Id))
		what.markup(link.Description)
		what.properties(
			[]string{"Source", what.ref(link.Source)},
			[]string{"Target", what.ref(link.Target)},
			[]string{"Protocol", markdownText(link.Link.Protocol.String())},
			[]string{"Encrypted", yesNo(link.Encrypted)},
			[]string{"Authentication", markdownText(link.Link.Authentication.String())},
			[]string{"Identity", markdownText(linkIdentity(link.Link))},
			[]string{"Authorization", markdownText(link.Link.Authorization.String())},
			[]string{"Read-only", yesNo(link.Link.Readonly)},
			[]string{columnUsage, markdownText(link.Link.Usage.String())},
			[]string{columnTags, markdownText(link.Tags)},
			[]string{"VPN", yesNo(link.Link.VPN)},
			[]string{"IP-filtered", yesNo(link.Link.IpFiltered)},
			[]string{"Data sent", what.refs(link.DataSent)},
			[]string{"Data received", what.refs(link.DataReceived)},
		)
	}
}

func (what *markdownWriter) riskRules(view *reportView) {
	what.properties(
		[]string{"Threagile version", markdownText(view.Run.ThreagileVersion)},
		[]string{"Threagile build timestamp", markdownText(view.Run.BuildTimestamp)},
		[]string{"Threagile execution timestamp", markdownText(view.ExecutionTimestamp)},
		[]string{"Model filename", markdownText(view.Run.ModelFilename)},
		[]string{"Model hash (SHA256)", markdownCode(view.Run.ModelHash)},
	)
	what.paragraph("Threagile (see " + markdownLink("threagile.io", "https://threagile.io") + " for more details) " +
		"is an open-source toolkit for agile threat modeling, created by Christian Schneider (" +
		markdownLink("christian-schneider.net", "https://christian-schneider.net") + "): It allows to model an " +
		"architecture with its assets in an agile fashion as a YAML file directly inside the IDE. Upon execution of " +
		"the Threagile toolkit all standard risk rules (as well as individual custom rules if present) are checked " +
		"against the architecture model. At the time the Threagile toolkit was executed on the model input file the " +
		"following risk rules were checked:")
	rows := make([][]string, 0, len(view.RiskRules))
	for _, rule := range view.RiskRules {
		title := markdownText(rule.Category.Title)
		if rule.Skipped {
			title = strong("skipped") + " " + title
		}
		if rule.Kind != "" {
			title += " (" + muted(markdownText(rule.Kind)) + ")"
		}
		rows = append(rows, []string{
			title, markdownCode(rule.ID), markdownText(rule.Category.STRIDE.Title()),
			markdownInline(rule.Description), markdownInline(rule.DetectionLogic), markdownInline(rule.RiskAssessment),
		})
	}
	what.table([]markdownColumn{
		{"Risk rule", false},
		{"ID", false},
		{columnSTRIDE, false},
		{"Description", false},
		{"Detection", false},
		{"Rating", false},
	}, rows...)
}

func (what *markdownWriter) ratings(view *reportView) {
	columns := []markdownColumn{{"Name", false}, {"Value", true}, {"Description", false}}
	for _, ratings := range []struct {
		title  string
		values []viewRating
	}{{"Confidentiality Values", view.Confidentiality}, {"Criticality Values", view.Criticality}} {
		what.heading(3, "", ratings.title)
		rows := make([][]string, 0, len(ratings.values))
		for _, rating := range ratings.values {
			rows = append(rows, []string{
				markdownText(rating.Name), strconv.Itoa(rating.Value),
				markdownText(rating.Explanation),
			})
		}
		what.table(columns, rows...)
	}
}

func (what *markdownWriter) disclaimer(view *reportView) {
	author := markdownText(view.Author.Name)
	what.paragraph(author + " conducted this threat analysis using the open-source Threagile toolkit on the " +
		"applications and systems that were modeled as of this report's date. Information security threats are " +
		"continually changing, with new vulnerabilities discovered on a daily basis, and no application can ever be " +
		"100% secure no matter how much threat modeling is conducted. It is recommended to execute threat modeling and " +
		"also penetration testing on a regular basis (for example yearly) to ensure a high ongoing level of security " +
		"and constantly check for new attack vectors.")
	what.paragraph("This report cannot and does not protect against personal or business loss as the result of use " +
		"of the applications or systems described. " + author + " and the Threagile toolkit offers no warranties, " +
		"representations or legal certifications concerning the applications or systems it tests. All software " +
		"includes defects: nothing in this document is intended to represent or warrant that threat modeling was " +
		"complete and without error, nor does this document represent or warrant that the architecture analyzed is " +
		"suitable to task, free of other defects than reported, fully compliant with any industry standards, or fully " +
		"compatible with any operating system, hardware, or other application. Threat modeling tries to analyze the " +
		"modeled architecture without having access to a real working system and thus cannot and does not test the " +
		"implementation for defects and vulnerabilities. These kinds of checks would only be possible with a separate " +
		"code review and penetration test against a working system and not via a threat model.")
	what.paragraph("By using the resulting information you agree that " + author + " and the Threagile toolkit shall " +
		"be held harmless in any event.")
	what.paragraph("This report is confidential and intended for internal, confidential use by the client. The " +
		"recipient is obligated to ensure the highly confidential contents are kept secret. The recipient assumes " +
		"responsibility for further distribution of this document.")
	what.paragraph("In this particular project, a time box approach was used to define the analysis effort. This means " +
		"that the author allotted a prearranged amount of time to identify and document threats. Because of this, there " +
		"is no guarantee that all possible threats and risks are discovered. Furthermore, the analysis applies to a " +
		"snapshot of the current state of the modeled architecture (based on the architecture information provided by " +
		"the customer) at the examination time.")
	what.heading(3, "", "Report Distribution")
	what.paragraph("Distribution of this report (in full or in part like diagrams or risk findings) requires that this " +
		"disclaimer as well as the chapter about the Threagile toolkit and method used is kept intact as part of the " +
		"distributed report or referenced from the distributed parts.")
}
