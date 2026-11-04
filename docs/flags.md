# Flags

## Common flags

| Flag                             | Type                           | Description                                                                                 | Default Value  |
|----------------------------------|--------------------------------|---------------------------------------------------------------------------------------------| ---------------|
| `-config`                        | string(path to file)           | path to config file (more details [here](./config.md))                                      | ""             |
| `-model`                         | string(path to file)           | path to threagile model (more details [here](./model.md))                                   | threagile.yaml |
| `-interactive` or `--i`          | bool                           | turn on [interactive mode](./mode-interactive.md)                                           | false          |
| `-app-dir`                       | string(path to directory)      | optional directory with support files (example models, license, schema etc) that override the copies embedded in the binary | /app           |
| `-output`                        | string(path to directory)      | path to directory where generated results will be saved                                     | ""             |
| `-tmp-dir`                       | string(path to directory)      | path to directory where temporary files will be created                                     | dev/shm        |
| `-ignore-orphaned-risk-tracking` | bool                           | do not fail the application when risk tracking does not match any risk id                   | false          |
| `-skip-risk-rules`               | string (comma separated array) | allow to ignore certain rules                                                               | ""             |
| `-custom-risk-rules-plugin`      | string (comma separated array) | comma-separated list of plugins file names with custom risk rules to load                   | ""             |
| `-verbose` or `--v`              | bool                           | add more verbosity in output, perfect for debugging and troubleshooting                     | false          |

## Analyze flags

This flags is used when application run in [analyze mode](./mode-analyze.md)

| Flag                              | Type                 | Description                                                        | Default Value             |
|-----------------------------------|----------------------|--------------------------------------------------------------------| --------------------------|
| `-diagram-dpi`                    | int                  | [GraphViz dpi](https://graphviz.org/docs/attrs/dpi/)               | 100                       |
| `-background`                     | string(path to file) | path to pdf which will be used as background during pdf generation (a relative path is looked up in `-app-dir`; while left at the default and absent there, the embedded background is used) | background.pdf            |
| `-reportLogoImagePath`            | string(path to file) | path to logo image file which will be used in adoc report (while left at the default and absent, the embedded logo is used) | report/threagile-logo.png |
| `-generate-data-flow-diagram`     | bool                 | specify if data flow diagram shall be generated                    | true                      |
| `-generate-data-asset-diagram`    | bool                 | specify if data asset diagram shall be generated                   | true                      |
| `-generate-risks-json`            | bool                 | specify if JSON with risks shall be generated                      | true                      |
| `-generate-technical-assets-json` | bool                 | specify if JSON with technical assets shall be generated           | true                      |
| `-generate-stats-json`            | bool                 | specify if JSON with risk statistic shall be generated             | true                      |
| `-otm-json`                       | string(path to file) | file name of the [Open Threat Model (OTM)](./otm.md) JSON with the model and its risks | otm.json                  |
| `-skip-otm-json`                  | bool                 | skip generating the [Open Threat Model (OTM)](./otm.md) JSON        | false                     |
| `-generate-risks-excel`           | bool                 | specify if Excel with risks shall be generated                     | true                      |
| `-generate-tags-excel`            | bool                 | specify if Excel with tags shall be generated                      | true                      |
| `-generate-report-pdf`            | bool                 | specify if PDF with the analyse report shall be generated          | true                      |
| `-generate-report-adoc`           | bool                 | specify if adoc report with the analysis  shall be generated       | true                      |
| `-report-html`                    | string(path to file) | file name of the self-contained [HTML report](./html-report.md)    | report.html               |
| `-skip-report-html`               | bool                 | skip generating the [HTML report](./html-report.md)                | false                     |
| `-fail-on`                        | string(severity)     | exit with status 2 when unchecked risks of this severity or higher remain, see [Failing CI on unchecked risks](./mode-analyze.md#failing-ci-on-unchecked-risks) | (off)                     |

## Import flags

These flags are used by the `import-otm` [command](./commands.md), which converts an [Open Threat Model (OTM)](./otm.md) file into a Threagile model

| Flag      | Type                                | Description                                                                                       | Default Value |
|-----------|-------------------------------------|---------------------------------------------------------------------------------------------------| --------------|
| `-otm`    | string(path to file)                | path to the OTM file (JSON or YAML) to import                                                     | ""            |
| `-output` | string(path to directory or file)   | the model file to write when it ends in `.yaml` or `.yml`, else the directory for `threagile.yaml`; an existing file is not overwritten | ""            |

## Server flags

This flags is used when application run in [server mode](./mode-server.md)

| Flag           | Type                      | Description                                             | Default Value  |
|----------------|---------------------------|---------------------------------------------------------| ---------------|
| `-server-dir`  | string(path to directory) | path to directory where the server stores its data, such as the API keys (the web UI is embedded in the binary) | /data          |
| `-server-port` | int                       | which port will be used to run the server               | 8080           |
