# Diagrams

Threagile draws two diagrams of a model: `data-flow-diagram.png` with the technical assets, their
communication links and the trust boundaries, and `data-asset-diagram.png` with the data assets and
where they are processed and stored. The reports embed both. Add `--keep-diagram-source-files` to
also keep their Graphviz sources (`.gv`), and set `"AddLegend": true` in the
[config](./config.md) to draw the legend below into the data-flow diagram.

## Data-flow diagram

### Technical assets

The shape is the type of the asset:

| Shape | Asset |
|-------|-------|
| box | `external-entity` |
| ellipse | `process` |
| cylinder | `datastore` |
| octagon | any type with `used_as_client_by_human: true` |

A double border marks a `redundant` asset, and cell borders inside the label a `multi_tenant` one.
The label shows the technologies, the size, the title and the relative attacker attractiveness
(RAA): where the attractiveness of the asset, from the ratings and quantities of its data and its
links, lies between the least (1 %) and the most attractive asset (100 %) of the model.

The colors show the ratings of the asset, counting the data assets it processes and stores:

| Element | Red | Amber | Black |
|---------|-----|-------|-------|
| title | `mission-critical` integrity | `critical` integrity | lower integrity |
| border | `strictly-confidential` | `confidential` | lower confidentiality |

The border is dotted when the asset processes no data assets, or is out of scope. The fill shows,
in this order:

| Fill | Asset |
|------|-------|
| light pink | processes and stores no data, has an unknown technology, or has no communication links: likely a gap in the model |
| light blue | on the `internet` |
| lavender | `out_of_scope` |
| yellow | with `custom_developed_parts` |
| gray | any other |

The fill is darker for `physical` machines, brighter for `container`s and even brighter for
`serverless` ones.

### Communication links

An arrow points from the asset that initiates the connection to its target. The arrowhead at the
target is filled for a link that writes and hollow for a `readonly` one; a second, hollow
arrowhead at the initiator shows that data is also received back.

The color of the arrow is the first of these that applies:

| Color | Link |
|-------|------|
| pink, thick | sends and receives no data assets, or has the protocol `unknown-protocol`: likely a gap in the model |
| light gray | `usage: devops` |
| dark blue | `vpn: true` |
| brown | `ip_filtered: true` |
| red | sends or receives `strictly-confidential` data |
| amber | sends or receives `confidential` data |
| black | any other |

The line is dotted when the link transfers no data, dashed for `devops` usage, and solid otherwise.
The label is the protocol, red when the link transfers `mission-critical` data, amber for
`critical` data and gray otherwise. `diagram_tweak_suppress_edge_labels: true` leaves the labels
out.

### Trust boundaries

Each trust boundary is a dashed frame labelled with its title and type. A boundary with nested
boundaries has a thicker frame, and a nested boundary a darker background. A
`network-policy-namespace-isolation` boundary has a light blue background, and an
`execution-environment` boundary a dotted frame on an ivory background. Shared runtimes are not
drawn.

### Layout tweaks

These fields of the model change the layout when Graphviz places assets badly:

| Field | Effect |
|-------|--------|
| `diagram_tweak_layout_left_to_right` | ranks the assets from left to right instead of top to bottom |
| `diagram_tweak_edge_layout` | `ortho` (the default), `spline`, `polyline`, `curved` or `false` for the lines of the links |
| `diagram_tweak_nodesep`, `diagram_tweak_ranksep` | more space between the assets of a rank, and between the ranks |
| `diagram_tweak_same_rank_assets` | asset ids to put on the same rank; they may not be inside trust boundaries |
| `diagram_tweak_invisible_connections_between_assets` | `source-id:target-id` pairs joined by an invisible link, to pull them together |
| `diagram_tweak_order` (technical asset) | the left to right order of the assets within a trust boundary |
| `diagram_tweak_weight` (communication link) | heavier links are drawn shorter and straighter |
| `diagram_tweak_constraint` (communication link) | `true` keeps the link from affecting the ranks of the assets |

## Data-asset diagram

Each data asset is a box, filled by the highest data breach probability of the risks still at
risk that involve it: dark red for `probable`, orange-brown for `possible`, dark blue for
`improbable` and gray when none are left. Each technical asset that processes or stores data is a box filled by the highest
severity of its risks still at risk, in the colors of the reports (red for `critical`, dark
red for `high`, orange for `elevated`, orange-brown for `medium`, dark blue for `low`), and gray
when none are left or the asset is out of scope. A solid blue arrow leads from a data asset to the asset
that stores it, and a dashed gray one to an asset that only processes it.
