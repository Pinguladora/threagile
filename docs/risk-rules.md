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
| Confused Deputy Agent (`confused-deputy-agent`) | agents that act for users (an incoming link with identity `end-user`, or from a client of humans) and reach assets with confidential or critical data with identity `service-account` or `workload`, directly or through the tools of an MCP server | none | the most sensitive asset reached; likely when the agent takes untrusted content | ASI03, LLM06, NHI9, MAESTRO layer 3 |

Model a hosted model you call as a service (like a commercial LLM API) as an
out-of-scope `llm` asset, so that the rules judge your use of it rather than the
model itself. A language model on the internet is no source of internet content: its
responses come from the model. Mark agents whose actions a human approves, or the single links that
need an approval, with the `human-in-the-loop` tag, and add it to `tags_available`.

[`demo/ai-agent/threagile.yaml`](../demo/ai-agent/threagile.yaml) models an AI
support assistant with all five AI technologies; analyze it to see the AI rules at work.

## OT rules

The OT rules model the threats of industrial control systems. They use the technologies
`plc`, `rtu`, `safety-controller`, `field-device`, `hmi`, `scada-server`, `historian`
and `engineering-workstation`, and the industrial control protocols `modbus`, `dnp3`,
`iec-104`, `iec-61850`, `s7comm`, `ethernet-ip`, `profinet`, `bacnet`, `opc-classic`
and `opc-ua`, with the secure variants `modbus-security`, `dnp3-encrypted` and
`opc-ua-encrypted`. Each OT rule lists the requirements of IEC 62443-3-3, the
techniques of MITRE ATT&CK for ICS and the other standards it covers in its
`references`.

The rules follow the zones of the Purdue model. Every OT asset except a historian
belongs into a *control zone*; IT assets, which are neither OT assets nor in the
*industrial DMZ*, should reach the control zones only through the DMZ. A historian is in
the DMZ; tag the other assets there, like a jump host, with `industrial-dmz` and add the
tag to `tags_available`. An asset *reaches IT* when it is on the internet or has a
communication link with an IT asset.

| Rule (id) | Fires on | Tags | Rated by | References |
|-----------|----------|------|----------|------------|
| Direct IT/OT Communication (`direct-it-ot-communication`) | links, in either direction, between an asset of a control zone and an IT asset | `industrial-dmz` puts an asset into the DMZ | the integrity and availability of the OT asset, very high for safety controllers; very likely when the IT asset is on the internet | IEC 62443-3-3 SR 5.1 and SR 5.2, ATT&CK for ICS T0883 and T0886, NIST SP 800-82 |
| Insecure Control Protocol (`insecure-control-protocol`) | non-readonly links into controllers and field devices over an industrial control protocol without its secure variant | none | the same; very likely from the internet, likely from an asset that is or reaches IT or across a network trust boundary | IEC 62443-3-3 SR 1.2 and SR 3.1, ATT&CK for ICS T0855 and T0830, NIST SP 800-82 |
| Missing Safety System Independence (`missing-safety-system-independence`) | non-readonly links into a safety controller from anything but a dedicated safety engineering workstation, which changes no other controllers | none | very high impact; likelihood as above | IEC 61511, ATT&CK for ICS T0880 and T0843, IEC 62443-3-3 SR 5.1, NIST SP 800-82 |

Industrial control protocols cannot carry the authentication that the
`missing-authentication` and `missing-authentication-second-factor` rules ask for, so
these rules skip links over the insecure ones and leave them to
`insecure-control-protocol`. The `unencrypted-communication` rule still reports them.

[`demo/ot-plant/threagile.yaml`](../demo/ot-plant/threagile.yaml) models a water
treatment plant with an industrial DMZ, a remote pump station and a chlorine safety
system; analyze it to see the OT rules at work.

## Access rules

These rules judge the [authentication, identity and authorization](./model.md#authentication-identity-and-authorization-of-links)
of communication links, and the policy decision points that services externalize their authorization to. Links
whose authorization is `unknown`, or whose authentication is `token` with an open lifetime, are skipped by the rules
that depend on them, so models that do not set these fields get no findings from them.

| Rule (id) | Fires on | Rated by | References |
|-----------|----------|----------|------------|
| Long-Lived Credentials (`long-lived-credentials`) | links into assets with confidential or critical data authenticated with `long-lived-token`, or with `credentials` by a caller no human uses, unless the identity is `workload` | the data of the target; likely from the internet, from clients of humans or across a network trust boundary | OWASP NHI7 and NHI2 |
| Missing Object-Level Authorization (`missing-object-level-authorization`) | links into non-datastore assets with confidential or critical data that act for users (identity `end-user` or a client of humans) with authorization `none`, `authenticated-only` or `function-level` | the data of the target, one step higher without function-level authorization; very likely from the internet | OWASP API1 and API5 |
| Missing Policy Decision Point Redundancy (`missing-policy-decision-point-redundancy`) | policy decision points that are not redundant and that other assets ask over the network | the availability of the services that ask it | AuthZEN Authorization API, NIST SP 800-162 |
| Unprotected Authorization Decisions (`unprotected-authorization-decisions`) | links to a policy decision point that are unauthenticated or unencrypted | the data of the service that asks; likely across a network trust boundary | AuthZEN Authorization API, NIST SP 800-162 |
| Human Use of Machine Identity (`human-use-of-machine-identity`) | links into assets with confidential or critical data from clients of humans with identity `service-account` or `workload` | the data of the target; likely | OWASP NHI10, ASI03 |
| Shared Machine Account (`shared-machine-account`) | in-scope assets whose links name an `account` that links of other assets name too, with identity `service-account` or `workload` | the data of all targets of the account; likely when the callers are in different trust boundaries | OWASP NHI9, ASI03 |

The shared account rule needs the optional `account` of a link, which names the account behind a machine identity;
links without one are skipped.

[`demo/ai-agent/threagile.yaml`](../demo/ai-agent/threagile.yaml) sets these fields on all its links; its order
service and agent check access per function only, which the object-level rule reports. In
[`demo/example/threagile.yaml`](../demo/example/threagile.yaml), an administrator shares the database account of
the ERP system.

## Risk ids of Push instead of Pull Deployment

Push instead of Pull Deployment creates one risk per deployment target, with the id
`push-instead-of-pull-deployment@<build pipeline>@<deployment target>`. Earlier
versions gave all risks of a build pipeline the same id,
`push-instead-of-pull-deployment@<build pipeline>`, so a `risk_tracking` entry for
that id now matches no risk and is reported as orphaned. Replace it with one entry
per target, or with `push-instead-of-pull-deployment@<build pipeline>@*` to track
all of the pipeline's targets at once.
