# Open Threat Model (OTM)

[Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) is IriusRisk's open,
tool-neutral threat model format. Threagile writes and reads **OTM 0.2.0**, the latest released
version.

* `analyze-model` writes the analyzed model, with its risks, as `otm.json` (see
  [analyze mode](./mode-analyze.md)). `--otm-json` names the file, `--skip-otm-json` skips it;
  the config keys are `JsonOTMFilename` and `SkipOTMJSON`.
* `import-otm` turns an OTM file, JSON or YAML, into a threagile model YAML file:

  ```sh
  threagile import-otm --otm model.otm.json --output imported
  threagile analyze-model --model imported/threagile.yaml --output out
  ```

  `--output` names the model file when it ends in `.yaml` or `.yml`, and otherwise the folder to
  write `threagile.yaml` into. An existing file is not overwritten. The command prints a note for
  every value it had to default and everything it could not carry over, and it analyzes the model
  before writing it.

Threats are **not** imported: threagile generates the risks from the model when it analyzes it.

The output validates against the official [OTM JSON schema](../pkg/otm/testdata/otm_schema.json),
which the tests check for the example and stub models. The schema is copied unchanged from the
OpenThreatModel repository and is published under the Apache License 2.0, as it says itself; see
its `.license` file.

## Threagile to OTM

| Threagile | OTM | Notes |
| --- | --- | --- |
| `title` | `project.name`, `project.id` | the id is the title in lower case with hyphens |
| `application_description` | `project.description` |  |
| `author.name`, `author.contact` | `project.owner`, `project.ownerContact` |  |
| `tags_available` | `project.tags` |  |
| trust boundary | `trustZones` | `type` is the threagile type, `parent` the boundary it is nested in, `trustRating` see below |
| (assets in no trust boundary) | trust zone `outside-trust-boundaries` | OTM requires each component to have a parent; this zone, rated 0, is only added when needed, takes a `-2`, `-3`, … suffix if a trust boundary already has that id, and is marked with the attribute `threagile:outside-trust-boundaries` |
| technical asset | `components` | `type` is the first technology, `parent` the trust boundary, `assets` the data assets processed and stored |
| communication link | `dataflows` | id `<source>><link>`, `assets` all data assets sent or received; `bidirectional` when the link sends data and receives some back, which the data-flow diagram draws with a double hollow tail |
| data asset | `assets` | `risk` holds the CIA rating as a score (see below), `risk.comment` its justification |
| risk category with risks | `threats` and `mitigations` | the threat has the category's description, STRIDE as `categories`, `CWE-<n>` as `cwes`, the highest likelihood and impact of its risks, and the impact text as `impactComment`; its mitigation `<category>-mitigation` has the action as name, the mitigation text as description, and a `riskReduction` of 100 |
| risk | threat instance | at the dataflow of its most relevant communication link, else the component of its most relevant technical asset, else the components of its data breach assets; the state follows the risk tracking status (below) |

Every list is sorted by id, so the same model always gives the same file. An element lists each
threat once per state: OTM threat instances name only their threat and state, so several risks of
a category at one element, such as risks about different data assets, are a single instance.

Threagile details without an OTM field go into the element's `attributes`, named `threagile:`
and the field name of the model YAML file: the type, usage, size, machine, encryption, owner,
CIA and its justification, the flags (`internet`, `out_of_scope`, ...), further technologies and
data formats of a technical asset; the protocol, authentication, authorization, usage, flags and
data assets sent and received of a link; the usage, quantity, origin, owner and tags of a data
asset; the tags of a trust boundary; the business criticality and date of the model; and the
function, ASVS chapter and cheat sheet of a threat and the check of its mitigation. Lists are
comma-separated. They let a threagile model come back from OTM as it was, but for what the
[last section](#what-does-not-survive-the-trip) lists.

### Scores

OTM rates from 0 to 100. Threagile's levels are spread evenly over that range:

| Score | Confidentiality | Integrity, availability | Likelihood | Impact |
| --- | --- | --- | --- | --- |
| 0 | `public` | `archive` |  |  |
| 25 | `internal` | `operational` | `unlikely` | `low` |
| 50 | `restricted` | `important` | `likely` | `medium` |
| 75 | `confidential` | `critical` | `very-likely` | `high` |
| 100 | `strictly-confidential` | `mission-critical` | `frequent` | `very-high` |

The import takes the nearest level of a score.

### Trust ratings

A trust boundary that protects a smaller part of the network is trusted more than one around a
whole network, and a dedicated hoster or cloud provider less than one's own premises.

| Trust boundary type | `trustRating` |
| --- | --- |
| (outside of all trust boundaries) | 0 |
| `network-dedicated-hoster` | 40 |
| `network-cloud-provider` | 40 |
| `network-on-prem` | 50 |
| `network-virtual-lan` | 60 |
| `network-cloud-security-group` | 60 |
| `network-policy-namespace-isolation` | 70 |
| `execution-environment` | that of the zone it is nested in, 50 at the top level: a logical group, not a protection |

### Threat states

OTM leaves the states open; its examples use `exposed` and `mitigated` for threats and `required`
and `implemented` for mitigations.

| Risk tracking status | Threat instance state | Mitigation state |
| --- | --- | --- |
| `unchecked` | `exposed` | `recommended` |
| `in-discussion` | `exposed` | `recommended` |
| `in-progress` | `exposed` | `required` |
| `accepted` | `accepted` | `rejected` |
| `mitigated` | `mitigated` | `implemented` |
| `false-positive` | `not-applicable` | `not-applicable` |

## OTM to threagile

| OTM | Threagile | Notes |
| --- | --- | --- |
| `project.name` | `title` |  |
| `project.description` | `application_description` |  |
| `project.owner`, `project.ownerContact` | `author.name`, `author.contact` |  |
| `project.tags` | `tags_available` | with every tag the elements use, as threagile requires |
| `trustZones` | `trust_boundaries` | `type` when it is a threagile type; a parent zone lists it in `trust_boundaries_nested`; the zone marked `threagile:outside-trust-boundaries` is left out |
| `components` | `technical_assets` | `type` is the technology when threagile knows it; `parent` puts it in that trust boundary; `assets` become the data assets processed and stored |
| `dataflows` | `communication_links` of the source asset | `destination` is the target; `assets` are sent, and received too when the flow is `bidirectional`, unless `threagile:` attributes say which are sent and received |
| `assets` | `data_assets` | the CIA scores become the nearest levels, `risk.comment` the justification |
| `threats`, `mitigations`, threat instances | (not imported) | threagile generates the risks itself |
| `threagile:` attributes | the fields they name | other attributes are left out |

Threagile keys trust boundaries, assets and links by their name and takes ids of letters, digits
and hyphens only. Other ids are rewritten (a note says how), and a name that is taken already gets
the element's id appended; the names of the links of one asset need to differ in more than case.

A component nested in another component goes into the trust boundary of that one, as threagile
does not nest technical assets; a trust zone nested in a component becomes a top-level boundary.
Dataflows that do not lead from a component to a component, and references to unknown elements,
are left out with a note.

### Defaults

The fields that threagile requires and the OTM file has neither a field nor a `threagile:`
attribute for get these values. Where the right value is unknown they lean towards more risks
rather than fewer, so review them.

| Field | Default |
| --- | --- |
| `business_criticality` | `important` |
| trust boundary `type` | `network-on-prem` |
| technical asset `technology` (unknown component type) | `unknown-technology` |
| technical asset `type` | `process` |
| technical asset `size` | `application` |
| technical asset `machine` | `virtual` |
| technical asset `encryption` | `none` |
| technical asset `confidentiality` | `internal` |
| technical asset `integrity`, `availability` | `operational` |
| `usage` of technical assets, links and data assets | `business` |
| link `protocol` | `unknown-protocol` |
| link `authentication`, `authorization` | `none` |
| data asset `quantity` | `few` |

A technical asset's CIA rating is raised to that of its data assets when threagile analyzes the
model, so the low defaults do not hide sensitive data.

## What does not survive the trip

A threagile model that goes to OTM and back keeps its trust boundaries, technical assets,
communication links and data assets with all their fields but the diagram tweaks, and so the risks
that analysis finds from them. Lost are:

* risk tracking: threats are not imported, so every risk of the imported model is unchecked;
* custom risk categories and their individual risks;
* shared runtimes, and with them the risks about them;
* questions, abuse cases, security requirements, the management summary, the business and
  technical overviews, contributors and the author's homepage;
* the diagram tweaks of the model, its assets and links.

The OTM file holds the technical assets as analyzed: with the CIA rating raised to that of their
data assets, and processing the data assets that the analysis adds. Analyzing the imported model
arrives at the same values.
