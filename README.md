# Threagile

[![Threagile Community Chat](https://badges.gitter.im/Threagile/community.svg)](https://gitter.im/Threagile/community)

## Agile Threat Modeling Toolkit
Threagile (see [threagile.io](https://threagile.io) for more details) is an open-source toolkit for
agile threat modeling:

It allows to model an architecture with its assets in an agile fashion as a YAML file directly inside the IDE.
Upon execution of the Threagile toolkit all standard risk rules (as well as individual custom rules if present)
are checked against the architecture model. You can find more information about model schema [here](./docs/model.md),
the values of its fields in [types](./docs/types.md), and how to read the diagrams in [diagrams](./docs/diagrams.md).

The tool have various [commands](./docs/commands.md) and is highly configurable via [flags](./docs/flags.md) and [config](./docs/config.md).

We know that modifying yaml file via text editor may be tough and to simplify it we introduced:

- [includes](./docs/includes.md)
- [macros](./docs/macros.md)
- [editor support](./docs/model.md#editor-support) for validation and completion with the schema

Custom risk rules can be written as YAML scripts without compiling Go code. See the [script language reference](./docs/scripts/language-reference.md), the [guide for writing custom risk rules](./docs/scripts/guide.md), and how to [test your scripts](./docs/scripts/testing.md).

Models can be exchanged with other threat modeling tools as [Open Threat Model (OTM)](./docs/otm.md) files: the analysis writes `otm.json`, and `import-otm` turns an OTM file into a model.

Efforts on UI are ongoing and there are few attempts to do it although that is far from being ready.

[Here](./docs/how-to.md) may be useful use cases on how others are using the tool and may be helpful to simplify onboarding of Threagile tool for your team.

## Installation

Install the binary with Go (1.27 or newer); it is static and embeds everything it needs, including the
diagram renderer, so nothing else has to be installed:

```shell
go install github.com/Pinguladora/threagile/cmd/threagile@latest
```

Or run the container image `ghcr.io/pinguladora/threagile`, which holds only the binary. The image is
published with the releases; until then, build it locally with `mise run snapshot:container`.

## Usage

Start from the example model or from a stub, then analyze the model:

```shell
threagile create-example-model --output .   # writes threagile-example-model.yaml
threagile create-stub-model --output .      # writes threagile-stub-model.yaml
threagile analyze-model --model threagile.yaml --output out
```

`analyze-model` writes into the output folder:

| File | What it is |
|------|------------|
| `THREAT_MODEL.md` | the [report as Markdown](./docs/markdown-report.md), with Mermaid diagrams, to keep in the repository |
| `report.html` | the report as a single self-contained HTML page |
| `report.pdf`, `adocReport/` | the report as PDF and as AsciiDoc |
| `data-flow-diagram.png`, `data-asset-diagram.png` | the diagrams; add `--keep-diagram-source-files` to also keep their Graphviz sources (`.gv`) |
| `risks.json`, `technical-assets.json`, `stats.json` | the results for other tools |
| `risks.xlsx`, `tags.xlsx` | the risks and the tags as spreadsheets |
| `otm.json` | the model as [Open Threat Model](./docs/otm.md) |

Each output can be skipped with its `--skip-...` flag, see `threagile analyze-model --help`. To fail a CI
build on risks nobody has looked at yet, add `--fail-on high`: the analysis then exits with status 2 when
unchecked risks of that severity or higher remain. With `--baseline <earlier risks.json>` the gate only fails
on risks that are new or newly reached that severity, and the reports show what changed (see
[analyze mode](./docs/mode-analyze.md#comparing-with-a-baseline)).

Other commands:

```shell
threagile explain risk 'unencrypted-asset@*'   # why risks were found, and how they are rated and tracked
threagile explain rules                         # what each risk rule checks
threagile list-types                            # the enum values usable in a model
threagile create-editing-support --output .     # schema.json and live templates for your IDE
threagile import-otm --otm model.otm.json --output imported
threagile server --server-port 8080             # the REST API and the model editor
```

With the container, run it as your own user so that it can write into the mounted folder:

```shell
docker run --rm -it --user "$(id -u):$(id -g)" -v "$(pwd)":/work -w /work \
  ghcr.io/pinguladora/threagile analyze-model --model threagile.yaml --output out
```

## Releases

The information about releases can be found at [releases page](./docs/releases.md).

## Contribution

You are very welcome to contribute into the project in any way. If you'd like to add new feature or fix the bug in the code base  please follow [contribution guide](./CONTRIBUTING.md).

Otherwise please create GitHub discussion or issue and contributors will find some time to respond.
