# Flags

<!-- Generated from the commands by `go test ./internal/threagile -update`; do not edit. -->

Every flag can also be set in the [config file](./config.md). Every command takes these flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--add-model-title` | bool | `false` | add model title |
| `--app-dir` | string | `/app` | optional folder with files that override the ones embedded in the binary |
| `--background` | string | `background.pdf` | (deprecated, ignored: the PDF report, rendered by typst, has no background template) template pdf file |
| `--backup-history-files-to-keep` | int | `50` | number of backup history files to keep |
| `--baseline` | string |  | risks json of an earlier analysis to compare with; --fail-on then only fails on new or escalated risks |
| `--config` | string |  | config file |
| `--custom-risk-rules-plugin` | string |  | comma-separated list of plugins file names with custom risk rules to load |
| `--data-asset-diagram-dot` | string | `data-asset-diagram.gv` | data asset diagram DOT file |
| `--data-asset-diagram-png` | string | `data-asset-diagram.png` | data asset diagram PNG file |
| `--data-dir` | string | `/data` | data directory |
| `--data-flow-diagram-dot` | string | `data-flow-diagram.gv` | data flow diagram DOT file |
| `--data-flow-diagram-png` | string | `data-flow-diagram.png` | data flow diagram PNG file |
| `--diagram-dpi` | int | `100` | DPI used to render: maximum is 300 |
| `--execute-model-macro` | string |  | macro to execute |
| `--fail-on` | string |  | exit with status 2 when unchecked risks of this severity or higher remain (low, medium, elevated, high, critical) |
| `--generate-data-asset-diagram` | bool | `true` | (deprecated, use the matching --skip flag) generate data asset diagram |
| `--generate-data-flow-diagram` | bool | `true` | (deprecated, use the matching --skip flag) generate data flow diagram |
| `--generate-report-pdf` | bool | `true` | (deprecated, use the matching --skip flag) generate report pdf, including diagrams |
| `--generate-risks-excel` | bool | `true` | (deprecated, use the matching --skip flag) generate risks excel |
| `--generate-risks-json` | bool | `true` | (deprecated, use the matching --skip flag) generate risks json |
| `--generate-stats-json` | bool | `true` | (deprecated, use the matching --skip flag) generate stats json |
| `--generate-tags-excel` | bool | `true` | (deprecated, use the matching --skip flag) generate tags excel |
| `--generate-technical-assets-json` | bool | `true` | (deprecated, use the matching --skip flag) generate technical assets json |
| `--ignore-orphaned-risk-tracking` | bool | `false` | ignore orphaned risk tracking (just log them) not matching a concrete risk |
| `--imported-model` | string |  | imported input model yaml file |
| `--interactive`, `-i` | bool | `false` | interactive mode |
| `--keep-diagram-source-files` | bool | `false` | keep diagram source files |
| `--key-dir` | string | `keys` | key folder location |
| `--model` | string | `threagile.yaml` | input model yaml file |
| `--otm` | string |  | Open Threat Model (OTM) file to import with import-otm |
| `--otm-json` | string | `otm.json` | Open Threat Model (OTM) JSON file |
| `--output` | string | `.` | output directory |
| `--plugin-dir` | string | `/app` | plugin directory |
| `--report` | string | `report.pdf` | report file |
| `--report-html` | string | `report.html` | HTML report file |
| `--report-md` | string | `THREAT_MODEL.md` | Markdown report file |
| `--reportLogoImagePath` | string | `report/threagile-logo.png` | report logo image |
| `--risks-excel` | string | `risks.xlsx` | risks Excel file |
| `--risks-json` | string | `risks.json` | risks JSON file |
| `--server-dir` | string | `/data` | base folder for server mode |
| `--server-port` | int | `8080` | server port |
| `--skip-data-asset-diagram` | bool | `false` | skip generating data asset diagram |
| `--skip-data-flow-diagram` | bool | `false` | skip generating data flow diagram |
| `--skip-otm-json` | bool | `false` | skip generating Open Threat Model (OTM) json |
| `--skip-report-html` | bool | `false` | skip generating report html |
| `--skip-report-md` | bool | `false` | skip generating report markdown |
| `--skip-report-pdf` | bool | `false` | skip generating report pdf, including diagrams |
| `--skip-risk-rules` | string |  | comma-separated list of risk rules (by their ID) to skip |
| `--skip-risks-excel` | bool | `false` | skip generating risks excel |
| `--skip-risks-json` | bool | `false` | skip generating risks json |
| `--skip-stats-json` | bool | `false` | skip generating stats json |
| `--skip-tags-excel` | bool | `false` | skip generating tags excel |
| `--skip-technical-assets-json` | bool | `false` | skip generating technical assets json |
| `--stats-json` | string | `stats.json` | stats JSON file |
| `--tags-excel` | string | `tags.xlsx` | tags Excel file |
| `--technical-assets-json` | string | `technical-assets.json` | technical assets JSON file |
| `--technology` | string |  | file name of additional technologies |
| `--temp-dir` | string | `/dev/shm` | temporary folder location |
| `--verbose`, `-v` | bool | `false` | Verbose output |
