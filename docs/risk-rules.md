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
