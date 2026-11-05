package threagile

import "github.com/Pinguladora/threagile/pkg/report"

const (
	TempDir   = "/dev/shm"
	AppDir    = "/app"
	PluginDir = "/app"
	DataDir   = "/data"
	OutputDir = "."
	// ServerDir defaults to the data folder: the web UI is embedded in the binary,
	// so the server folder only holds the server's data (API keys and models).
	ServerDir = DataDir
	KeyDir    = "keys"

	DefaultServerPort = 8080

	InputFile                   = "threagile.yaml"
	ReportFilename              = "report.pdf"
	ExcelRisksFilename          = "risks.xlsx"
	ExcelTagsFilename           = "tags.xlsx"
	JsonRisksFilename           = "risks.json"
	JsonTechnicalAssetsFilename = "technical-assets.json"
	JsonStatsFilename           = "stats.json"
	JsonOTMFilename             = "otm.json"
	ReportHTMLFilename          = "report.html"
	ReportMarkdownFilename      = "THREAT_MODEL.md"
	TemplateFilename            = report.DefaultTemplateFilename
	ReportLogoImagePath         = report.DefaultReportLogoImagePath
	DataFlowDiagramFilenameDOT  = "data-flow-diagram.gv"
	DataFlowDiagramFilenamePNG  = "data-flow-diagram.png"
	DataAssetDiagramFilenameDOT = "data-asset-diagram.gv"
	DataAssetDiagramFilenamePNG = "data-asset-diagram.png"

	DefaultDiagramDPI               = 100
	DefaultGraphvizDPI              = 120
	MinGraphvizDPI                  = 20
	MaxGraphvizDPI                  = 300
	DefaultBackupHistoryFilesToKeep = 50
)

const (
	AnalyzeModelCommand         = "analyze-model"
	CreateExampleModelCommand   = "create-example-model"
	CreateStubModelCommand      = "create-stub-model"
	CreateEditingSupportCommand = "create-editing-support"
	ImportModelCommand          = "import-model"
	ImportOTMCommand            = "import-otm"
	MigrateModelCommand         = "migrate-model"
	ListTypesCommand            = "list-types"
	ListRiskRulesCommand        = "list-risk-rules"
	ListModelMacrosCommand      = "list-model-macros"
	Print3rdPartyCommand        = "print-3rd-party-licenses"
	PrintLicenseCommand         = "print-license"

	CreateCommand       = "create"
	ExplainCommand      = "explain"
	ListCommand         = "list"
	PrintCommand        = "print"
	QuitCommand         = "quit"
	RunCommand          = "run"
	PrintVersionCommand = "version"
)

const (
	EditingSupportItem = "editing-support"
	ExampleItem        = "example"
	LicenseItem        = "license"
	MacrosItem         = "macros"
	ModelItem          = "model"
	RiskItem           = "risk"
	RulesItem          = "rules"
	StubItem           = "stub"
	TypesItem          = "types"
)

const (
	ThreagileVersion = "1.0.0" // Also update into example and stub model files and openapi.yaml
	Logo             = "  _____ _                          _ _      \n" +
		" |_   _| |__  _ __ ___  __ _  __ _(_) | ___ \n" +
		"   | | | '_ \\| '__/ _ \\/ _` |/ _` | | |/ _ \\\n" +
		"   | | | | | | | |  __/ (_| | (_| | | |  __/\n" +
		"   |_| |_| |_|_|  \\___|\\__,_|\\__, |_|_|\\___|\n" +
		"                             |___/        " +
		"\nThreagile - Agile Threat Modeling"
	VersionText = "Documentation: https://threagile.io\n" +
		"Container image: " + containerImage + "\n" +
		"Sourcecode: https://github.com/Pinguladora/threagile\n" +
		"License: Open-Source (MIT License)\n" +
		"Version: " + ThreagileVersion + " (%v)"
	// The image runs as an unprivileged user, so the examples run it as the
	// caller's user to let it write into the mounted working directory.
	containerImage = "ghcr.io/pinguladora/threagile"
	containerUser  = " docker run --rm -it --user \"$(id -u):$(id -g)\""
	containerRun   = containerUser + " -v \"$(pwd)\":/work -w /work " + containerImage + " "
	Examples       = "Examples:\n\n" +
		"If you want to create an example model (via docker) as a starting point to learn about Threagile just run: \n" +
		containerRun + CreateExampleModelCommand + " --output .\n\n" +
		"If you want to create a minimal stub model (via docker) as a starting point for your own model just run: \n" +
		containerRun + CreateStubModelCommand + " --output .\n\n" +
		"If you want to execute Threagile on a model yaml file (via docker):  \n" +
		containerRun + "analyze-model --verbose --model threagile.yaml --output .\n\n" +
		"If you want to execute Threagile in interactive mode (via docker):  \n" +
		containerRun + "-i --verbose --model threagile.yaml --output .\n\n" +
		"If you want to run Threagile as a server (REST API) on some port (here 8080), keeping its data in " +
		"./server-data:  \n" +
		containerUser + " -p 8080:8080 -v \"$(pwd)/server-data\":/data " + containerImage + " server --server-port 8080\n\n" +
		"If you want to find out about the different enum values usable in the model yaml file: \n" +
		" docker run --rm -it " + containerImage + " " + ListTypesCommand + "\n\n" +
		"If you want to use some nice editing help (syntax validation, autocompletion, and live templates) in your " +
		"favourite IDE: \n" +
		containerRun + CreateEditingSupportCommand + " --output .\n\n" +
		"If you want to list all available model macros (which are macros capable of reading a model yaml file, " +
		"asking you questions in a wizard-style and then update the model yaml file accordingly): \n" +
		" docker run --rm -it " + containerImage + " " + ListModelMacrosCommand + "\n\n" +
		"If you want to execute a certain model macro on the model yaml file (here the macro add-build-pipeline): \n" +
		containerRun + "--model threagile.yaml --output . execute-model-macro add-build-pipeline"
	ThirdPartyLicenses = " - golang (Google Go License): https://golang.org/LICENSE\n" +
		" - go-yaml (MIT License): https://github.com/go-yaml/yaml/blob/v3/LICENSE\n" +
		" - graphviz (EPL License): https://graphviz.org/license/\n" +
		" - go-graphviz (MIT License): https://github.com/goccy/go-graphviz/blob/master/LICENSE\n" +
		" - wazero (Apache License): https://github.com/tetratelabs/wazero/blob/main/LICENSE\n" +
		" - DejaVu fonts (Bitstream Vera License): https://dejavu-fonts.github.io/License.html\n" +
		" - gofpdf (MIT License): https://github.com/jung-kurt/gofpdf/blob/master/LICENSE\n" +
		" - go-chart (MIT License): https://github.com/wcharczuk/go-chart/blob/master/LICENSE\n" +
		" - excelize (BSD License): https://github.com/qax-os/excelize/blob/master/LICENSE\n" +
		" - graphics-go (BSD License): https://github.com/BurntSushi/graphics-go/blob/master/LICENSE\n" +
		" - google-uuid (BSD License): https://github.com/google/uuid/blob/master/LICENSE\n" +
		" - gin-gonic (MIT License): https://github.com/gin-gonic/gin/blob/master/LICENSE\n" +
		" - cobra-cli (Apache License): https://github.com/spf13/cobra-cli/blob/main/LICENSE.txt\n"
)
