# Model

Threagile model is defined in `yaml` and comply to [schema](../support/schema.json).

The most important field from where analysis is starting is `technical_assets`. Another type of assets is `data_assets` which is modelling which data assets will be stored, processed, sent by technical asset.

Each technical asset has fields to link between each other and with data assets:

- `communication_links` - describe how technical assets linked to each other, inside communication links there will be also important fields like `data_assets_sent` and `data_assets_stored`. A link through proxies, such as a load balancer and a WAF, lists them in `via` (see [connections through proxies](#connections-through-proxies-via)).
- `data_assets_processed`, `data_assets_stored` - describe which data assets processed or stored by the technical asset.

Also it is possible to identify in model `trust_boundaries` and `shared_runtime` to group technical assets under shared runtime or trust boundaries.

That is the most important fields to build the model. You can find more by reading [example](../demo/example/threagile.yaml)

The `author` of the model is shown on the reports, and further people who worked on it can be listed under `contributors` (each with `name`, `contact` and `homepage`, like the author); the PDF report lists them on its cover and the AsciiDoc report in its management summary.

After model is ready next steps would be running the tool in [analyze mode](./mode-analyze.md) to identify risks by [risk rules algorithms](./risk-rules.md).
This will generate a lot of useful reports which will overview the system in a different formats.

Some of identified risks are real risks, some of it is accepted risk therefore next important field would be `risk_tracking` where it would be possible to document risk analysis model.

## Connections through proxies (`via`)

A communication link can list, in order, the technical assets the connection passes through on its way to the target, such as a load balancer and a WAF:

```yaml
technical_assets:
  Customer Client:
    id: customer-client
    communication_links:
      Customer Traffic:
        target: apache-webserver
        via:
          - load-balancer
          - waf
        description: Link to the web server
        protocol: https
        authentication: session-id
        authorization: end-user-identity-propagation
        usage: business
        data_assets_sent:
          - customer-orders
```

Threagile turns such a link into one link per hop: `customer-client` → `load-balancer` → `waf` → `apache-webserver`. Diagrams, risk rules, reports, statistics, exports and risk tracking all see the hops as ordinary links. The source of each hop owns it, so the first hop is a link of the client and the next ones are links of the proxies, and the proxies process the data assets the link sends and receives.

Each hop copies the attributes of the link: `description`, `protocol`, `authentication`, `authorization`, `usage`, `tags`, `vpn`, `ip_filtered`, `readonly`, `data_assets_sent`, `data_assets_received` and the diagram tweaks. When a hop differs, for example because TLS ends at the load balancer and the rest of the way is plain `http`, or because the proxy authenticates with its own credentials, model the hops as explicit communication links of the proxies instead.

The hops have these titles and ids, which risk tracking uses:

| Hop | Title | Id |
|---|---|---|
| `customer-client` → `load-balancer` | Customer Traffic (hop 1 of 3) | `customer-client>customer-traffic>load-balancer` |
| `load-balancer` → `waf` | Customer Traffic (hop 2 of 3) | `customer-client>customer-traffic>waf` |
| `waf` → `apache-webserver` | Customer Traffic (hop 3 of 3) | `customer-client>customer-traffic>apache-webserver` |

The id of a hop is the id the link would have without `via` (the id of its source, `>`, and its title in lower case with hyphens), followed by `>` and the id of the asset the hop leads to. The link itself has no id of its own any more, so risks on it are tracked by the ids of its hops, such as `server-side-request-forgery@waf@apache-webserver@customer-client>customer-traffic>apache-webserver`. A modelled link has a single `>` in its id, so a hop never clashes with one. Adding `via` to a link, or changing it, changes the ids of the hops, so update the risk tracking of the link along with it.

Every entry of `via` must be the id of a technical asset other than the source and the target of the link, and may be listed only once. A proxy may be out of scope, like a CDN run by someone else: its hops are links of an out-of-scope asset, the same as if they were modelled by hand. When a link is defined in more than one [included](./includes.md) file, its `via` lists must be equal or missing.
