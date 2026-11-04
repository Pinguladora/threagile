# Analyze model

The output of running tool may be in different formats:

* `report.pdf` - most comprehensive report contained all information.
* `report.html` - the same report as a single, self-contained [HTML page](./html-report.md), to read in a browser or keep as a CI artifact.
* `risks.xlsx` and `risks.json` - list of identified risks in Excel and JSON formats.
* `data-asset-diagram.png` - image/dot file which contains all data assets and relationship between them.
* `data-flow-diagram.png` - image/dot file which contains all technical assets and relationship between them.
* `stats.json` - contains statistics of identified risks.
* `otm.json` - the model and its risks as an [Open Threat Model (OTM)](./otm.md) document, for other threat modeling tools.
* [adocReport](./docs/asciidoctor-report.md)

## Reproducible reports

The same model always produces the same diagrams, JSON, Excel, HTML and AsciiDoc files.
The only thing that changes between runs is the timestamp the reports are stamped
with (the report date when the model has no `date`, and the execution timestamp).
Set [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/)
to a Unix timestamp to fix it, for example to the time of the last commit:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) threagile analyze-model --model threagile.yaml --output out
```

All outputs are then byte-identical between runs, except `report.pdf`: the PDF
library numbers the objects of the imported background page in random order, so
the PDF bytes differ while its content stays the same.

## Failing CI on unchecked risks

`--fail-on <severity>` (or `"FailOn"` in the config file) turns the analysis into
a gate. When risks of that severity or higher are still unchecked, meaning they
have no `risk_tracking` entry or one with status `unchecked`, threagile writes the
reports as usual, lists those risks and exits with status 2. Any other error exits
with status 1. Severities are `low`, `medium`, `elevated`, `high` and `critical`.

Risks in any other status (in discussion, accepted, in progress, mitigated, false
positive) have been looked at, so they do not fail the gate. To let a new risk
through, add a `risk_tracking` entry for it to the model.

```sh
threagile analyze-model --model threagile.yaml --output out --fail-on high
```
