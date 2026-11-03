# Contributing to Threagile

:+1::tada: First of all, thanks for taking the time to contribute! :tada::+1:

All your contributions are very welcome, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

Thank you so much! :clap:

## Development

The toolchain is pinned with [mise](https://mise.jdx.dev/). Install mise, then from
the repository root:

```sh
mise trust     # once: allow this repository's mise config
mise install   # installs go, golangci-lint, goreleaser, hk, ... and the git hooks
```

`mise install` also runs `hk install --mise`, so the [hk](https://hk.jdx.dev/) hooks
check formatting, YAML, secrets and Conventional Commit messages on commit, and run
golangci-lint, the tests and the GitHub Actions audits before push.

Common tasks (`mise tasks` lists them all):

| Task | What it does |
| --- | --- |
| `mise run check` | The pre-commit gate: gofmt, vet, build, test, lint |
| `mise run analyze [model.yaml]` | Analyse a model (default: the bundled example) into `out/` |
| `mise run serve` | Run the REST server and model editor on :8080 |
| `mise run snapshot` | Local GoReleaser build of every release archive into `dist/` |
| `mise run debt` | Full lint report, including the findings inherited from upstream |

Lint only fails on findings introduced since `main`; the code inherited from
upstream still carries findings that are being burned down separately.

Main program is [threagile](./cmd/threagile/main.go).

### Development with Visual Studio Code

Start by navigating to `./cmd/threagile/main.go`, selecting `Run -> Add Configuration... -> Go: Launch file`. This will create launch.json at `./.vscode/launch.json`

Modify launch.json with this content and simply use `Run -> Start Debugging`/`Run -> Start Without Debugging`. Note that paths in `launch.json` under `"args":` are relative to the `main.go`.

Example `launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
          "name": "Launch Threagile Help Command",
          "type": "go",
          "request": "launch",
          "mode": "debug",
          "console": "integratedTerminal",
          "program": "${workspaceFolder}/cmd/threagile",
          "args": [
            "help",
            "--config",
            "./config.json",
          ]
        }
    ]
}
```

Where  config.json

```json
{
    "appFolder": "directory_with_support_files",
    "tempFolder": "./",
    "dataFolder": "./",
    "diagramDPI": 96,
    "inputFile": "./threagile-example-model.yaml",
    "ignoreOrphanedRiskTracking": true,
    "reportLogoImagePath": "/Users/Yevhen.Zavhorodnii/app/threagile-logo.png",
    "verbose": true
}
```

Where

```directory_with_support_files``` is a directory where support files are located:

```
app/
├─ [background.pdf](./report/template/background.pdf)
├─ [LICENSE.txt](./LICENSE.txt)
├─ [live-templates.txt](./support/live-templates.txt)
├─ [openapi.yaml](./support/openapi.yaml)
├─ [schema.json](./support/schema.json)
├─ [threagile-example-model.yaml](./demo/example/threagile.yaml)
├─ [threagile-logo.png](./report/threagile-logo.png)
├─ [threagile-stub-model.yaml](./demo/stub/threagile.yaml)
```

When everything is configured, select the Run and Debug menu on the left (picture of a play button with a bug) and run your configuration from there.

You can add additional configurations in `launch.json`, for example:

```json
    {
      "name": "Launch Threagile Analyze",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "console": "integratedTerminal",
      "program": "${workspaceFolder}/cmd/threagile",
      "args": [
        "analyze-model",
        "--ignore-orphaned-risk-tracking",
        "--model",
        "${workspaceFolder}/demo/example/threagile.yaml",
        "--app-dir",
        "/Users/Yevhen.Zavhorodnii/app",
        "--temp-dir",
        "${workspaceFolder}/tmp",
        "--output",
        "${workspaceFolder}/output",
        "--diagram-dpi",
        "96",
        "-v"
      ]
    }
```
Note that this configuration uses folders you will have to create in the project root: `tmp` and `output`.

Using any of the above configurations will allow you to use the vscode debugger, set breakpoints etc.

## Packages structure

After recent efforts on modularization the code those packages was added:

- ***cmd*** - contains programs which runs
  - threagile - the main program, documentation about can be found at main [readme](./README.md)
  - risk_demo - demo risk program which is demonstrating how to create custom risk rules
  - script - util program to test script rule against your model
- ***pkg*** - reused part
  - internal - details on how to run the application as part of cobra application and configuration
  - types - simple structs (except [parsedModel](./pkg/types/model.go) which needs to be moved to [model](./pkg/model) package as soon as cross circular dependencies will be solved)
  - examples - logic for generating useful examples for end user (like example or stub Threagile model)
  - risks - logic for risk (builtin and scripts) to be executed against model
  - macros - logic for macros logic ()
  - server - [gin server](https://gin-gonic.com/) to run some of commands via UI
  - report - logic to generate all kind of reports (JSON, PDF, Excel)
  - input - logic to read the model from file system
  - model - logic to analyze the model from package above (input)

![package structure](./docs/package-structure.png)

Currently it is not expected that any extra references will be added to the current architecture, so if it appears that adding extra dependency (effectively if you need to draw any extra line to make model above to expect reality) highly likely it may 2 options: some violation of [SOLID](https://en.wikipedia.org/wiki/SOLID)(particularly [dependency inversion principle](https://en.wikipedia.org/wiki/Dependency_inversion_principle)) is happening or current architecture require rethinking. Please raise a pull request and discuss this with other contributors.


## Contribution

To contribute the code simply make changes and create pull request. There is no strict rules about pull requests format like [this](https://www.pullrequest.com/blog/writing-a-great-pull-request-description/) however please take into consideration:

- it is easy to understand what the code change is achieving and why it was added
- new change is covered with unit tests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/); the hk `commit-msg` hook checks them, and releases are versioned from them with Cocogitto.
