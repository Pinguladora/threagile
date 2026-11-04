# Risk rules

Based on risk rules Threagile will analyze model and identify potential risks.

There are a lot of built in rules.

- DoS-risky Access Across Trust-Boundary;
- Incomplete Model;
- Missing Build Infrastructure;
- Missing File Validation;
- Accidental Secret Leak;
- Missing Cloud Hardening;
- Missing Network Segmentation;
- Missing Vault Isolation;
- Unnecessary Data Transfer;
- Missing Authentication;
- Missing Identity Propagation;
- Missing Web Application Firewall (WAF);
- Search-Query Injection;
- Unencrypted Communication;
- Unguarded Access From Internet;
- Container Base Image Backdooring;
- Container Platform Escape;
- Cross-Site Request Forgery (CSRF);
- Cross-Site Scripting (XSS);
- Push instead of Pull Deployment;
- XML External Entity (XXE);
- Code Backdooring;
- LDAP-Injection;
- Missing Hardening;
- Missing Identity Store;
- Path-Traversal;
- Unchecked Deployment;
- Wrong Communication Link Content;
- Missing Two-Factor Authentication (2FA);
- Missing Vault (Secret Storage);
- Mixed Targets on Shared Runtime;
- SQL/NoSQL-Injection;
- Unguarded Direct Datastore Access;
- Unnecessary Data Asset;
- Unnecessary Communication Link;
- Untrusted Deserialization;
- Wrong Trust Boundary Content;
- Missing Identity Provider Isolation;
- Server-Side Request Forgery (SSRF);
- Service Registry Poisoning;
- Unencrypted Technical Assets;
- Unnecessary Technical Asset;
- Public Cloud Asset Access;
- Publicly Shared Cloud Snapshot;
- Cross-Account Takeover;
- Denial of Service by Encryption Key Deletion.

Also there is available creation of [custom risk rules](./custom-risk-rules.md).

## Cloud rules and their tags

A threat model does not hold cloud configuration (bucket policies, snapshot sharing,
role trust policies or key deletion settings), so the cloud rules fire where the
model shows that a misconfiguration would matter. They count a technical asset as a
cloud asset when it, a trust boundary around it or a shared runtime it runs on is
tagged with a cloud provider tag (`aws`, `azure`, `gcp`, `ocp` or a sub-tag like
`aws:s3`), or when a trust boundary around it is of type `network-cloud-provider` or
`network-cloud-security-group`. Like the other rules they skip out-of-scope assets,
and they rate the impact from the CIA ratings at stake: medium, high from
`confidential` or `critical`, very high from `strictly-confidential` or
`mission-critical`. Service tags are read from the asset, a trust boundary around it
or its shared runtime.

| Rule (id) | Fires on | Tags | Rating |
|-----------|----------|------|--------|
| Missing Cloud Hardening (`missing-cloud-hardening`) | cloud trust boundaries, shared runtimes and assets | `aws`, `azure`, `gcp`, `ocp`, `aws:vpc`, `aws:ec2`, `aws:s3`, `aws:ebs`, `aws:apigateway`, `aws:lambda`, `aws:dynamodb`, `aws:rds`, `aws:sqs`, `aws:iam` | confidentiality, integrity, availability |
| Public Cloud Asset Access (`public-cloud-asset-access`, threagile#26) | cloud assets that process or store data and are tagged `aws:s3` or `aws:sqs`, or are a serverless file storage, data lake or message queue | `aws:s3`, `aws:sqs` | confidentiality, integrity, availability; likely when the asset is internet-facing or used from the internet |
| Publicly Shared Cloud Snapshot (`public-cloud-snapshot`, threagile#27) | cloud assets that store data and are tagged `aws:rds`, `aws:ebs` or `aws:ec2` (AMIs), or are a database or block storage | `aws:rds`, `aws:ebs`, `aws:ec2` | confidentiality |
| Cross-Account Takeover (`cross-account-takeover`, threagile#28) | communication links into an asset from an asset in another cloud account, i.e. another innermost `network-cloud-provider` trust boundary | none | confidentiality, integrity, availability of the target; likely when the source or the target is `multi_tenant` |
| Denial of Service by Encryption Key Deletion (`encryption-key-deletion`, threagile#29) | encrypted cloud assets that store data and are tagged with a key management service tag or communicate with a vault or HSM in the cloud (key stores themselves excluded) | `aws:kms`, `azure:keyvault`, `gcp:kms` | availability |

To opt an asset into the key deletion rule, model the key management service as a
`vault` asset in the cloud that the encrypted asset communicates with, or tag the
encrypted asset (or its trust boundary) with `aws:kms`, `azure:keyvault` or
`gcp:kms`. Add the tags you use to `tags_available`.

## AI rules

The AI rules model the threats of systems built on language models and agents. They
use the technologies `llm`, `ai-agent`, `vector-database`, `mcp-server` and
`model-registry`; the generic `ai` technology matches none of them. Each AI rule lists
the entries of the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/),
the OWASP Top 10 for Agentic Applications 2026 and the layers of the CSA MAESTRO
framework it covers in its `references`, which the reports, `risks.json` and the OTM
export show.

Several rules ask whether *untrusted content* reaches an asset. It does when the asset
is on the internet, is called across a network trust boundary, reads from an internet
asset directly or through a tool that does (like an MCP server with a web fetch tool),
or is sent requests by an internet asset or a client used by humans, directly or
through other assets: content passes on along the communication links.

| Rule (id) | Fires on | Tags | Rated by | References |
|-----------|----------|------|----------|------------|
| Prompt Injection (`prompt-injection`) | language models and agents that untrusted content reaches | none | the data the model or agent processes, one step higher for agents; very likely when it talks to the internet directly | LLM01, ASI01, MAESTRO layers 1 and 3 |
| Excessive Agency (`excessive-agency`) | non-readonly links of agents to assets with critical data, directly or through the tools of an MCP server; calls to language models are no actions | `human-in-the-loop` on the agent or the link skips it | the integrity of what the agent can change; likely when the agent takes untrusted content | LLM06, ASI02, ASI03, MAESTRO layer 3 |
| Vector Store Poisoning (`vector-store-poisoning`) | vector databases that a language model or agent communicates with | none | the data the models and agents using it process; likely when an asset taking untrusted content, or one across a network trust boundary, writes into it | LLM04, LLM08, ASI06, MAESTRO layer 2 |
| Unverified Model Supply Chain (`model-supply-chain`) | model registries, and language models that are custom-developed or communicate with a model registry | none | the data the models process | LLM03, LLM04, ASI04, MAESTRO layer 1 |
| Sensitive Data Disclosure through Model Output (`model-output-disclosure`) | language models and agents that untrusted content reaches and that process, or read from a vector database, confidential data | none | the confidentiality of what the model can read | LLM02, MAESTRO layer 1 |
| Unauthenticated MCP Server (`unauthenticated-mcp-server`) | links without authentication into an MCP server whose tools reach confidential or critical assets | none | what the tools reach; very likely for internet callers, likely for callers taking untrusted content | ASI02, ASI03, LLM06, MAESTRO layers 4 and 7 |

Model a hosted model you call as a service (like a commercial LLM API) as an
out-of-scope `llm` asset, so that the rules judge your use of it rather than the
model itself. A language model on the internet is no source of internet content: its
responses come from the model. Mark agents whose actions a human approves, or the single links that
need an approval, with the `human-in-the-loop` tag, and add it to `tags_available`.

[`demo/ai-agent/threagile.yaml`](../demo/ai-agent/threagile.yaml) models an AI
support assistant with all five AI technologies; analyze it to see the AI rules at work.

## Risk ids of Push instead of Pull Deployment

Push instead of Pull Deployment creates one risk per deployment target, with the id
`push-instead-of-pull-deployment@<build pipeline>@<deployment target>`. Earlier
versions gave all risks of a build pipeline the same id,
`push-instead-of-pull-deployment@<build pipeline>`, so a `risk_tracking` entry for
that id now matches no risk and is reported as orphaned. Replace it with one entry
per target, or with `push-instead-of-pull-deployment@<build pipeline>@*` to track
all of the pipeline's targets at once.
