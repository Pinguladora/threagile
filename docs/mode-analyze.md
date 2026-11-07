# Analyze model

The output of running tool may be in different formats:

* `report.pdf` - the same report as a PDF, see [the PDF report](#the-pdf-report) below.
* `report.html` - the same report as a single, self-contained [HTML page](./html-report.md), to read in a browser or keep as a CI artifact.
* `THREAT_MODEL.md` - the same report as a single [Markdown file](./markdown-report.md) with Mermaid diagrams, to keep in the repository or publish on a documentation site.
* `risks.xlsx` and `risks.json` - list of identified risks in Excel and JSON formats.
* `data-asset-diagram.png` - image/dot file which contains all data assets and relationship between them.
* `data-flow-diagram.png` - image/dot file which contains all technical assets and relationship between them.
* `stats.json` - contains statistics of identified risks.
* `otm.json` - the model and its risks as an [Open Threat Model (OTM)](./otm.md) document, for other threat modeling tools.

## Reproducible reports

The same model always produces the same diagrams, JSON, Excel, HTML, Markdown and PDF files.
The only thing that changes between runs is the timestamp the reports are stamped
with (the report date when the model has no `date`, and the execution timestamp).
Set [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/)
to a Unix timestamp to fix it, for example to the time of the last commit:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) threagile analyze-model --model threagile.yaml --output out
```

All outputs are then byte-identical between runs, `report.pdf` included.

## The PDF report

`report.pdf` has the chapters of the HTML and Markdown reports, with the diagrams as
vector graphics on landscape pages. [Typst](https://typst.app) renders it, so it is
only written when the `typst` command is on the `PATH`; without it, threagile warns
and writes the other outputs. The container image `ghcr.io/pinguladora/threagile` includes
typst.

The PDF conforms to PDF/A-3a, for archiving, and to PDF/UA-1, for accessibility: it
is tagged, its images have alternative texts and it embeds its fonts. `mise run
pdf:validate` renders the reports of the demos and checks both with
[veraPDF](https://verapdf.org), as CI does.

The `--background` template of earlier versions is no longer used; `--reportLogoImagePath`
still sets the logo of the title page.

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

## Comparing with a baseline

`--baseline <risks.json>` (or `"Baseline"` in the config file) compares the risks with
those of an earlier analysis, read from its `risks.json`. Threagile prints how many risks
are new, resolved, escalated (higher severity), de-escalated and unchanged, and lists the
new and the escalated ones. The HTML and Markdown reports get a chapter "Changes Since the
Baseline" after the risks by severity. Risks are matched by their synthetic id, the same id
that `risk_tracking` uses.

With a baseline, `--fail-on` only fails on unchecked risks that were not already at the
threshold in the baseline: the new ones and those whose severity rose to it. The gate can
then be turned on for a model that still has open risks, and fails when a change adds one.
The baseline is read before the analysis writes its outputs, so it can be the `risks.json`
in the output folder.

```sh
# on the main branch, keep the risks as the baseline
threagile analyze-model --model threagile.yaml --output baseline
# on a pull request, fail on new high or critical risks only
threagile analyze-model --model threagile.yaml --output out --baseline baseline/risks.json --fail-on high
```
