# Markdown report

`analyze-model` writes the report as `THREAT_MODEL.md` as well (see [analyze mode](./mode-analyze.md)):
one Markdown file with the chapters of the [HTML report](./html-report.md), in the same order, to keep
next to the code and publish on a documentation site. `--report-md` names the file and
`--skip-report-md` skips it; the config keys are `ReportMarkdownFilename` and `SkipReportMarkdown`.
`ReportConfiguration.HideChapter` and `HideEmptyChapters` leave out the same chapters as in the HTML
report.

The file needs nothing else: the data-flow and data mapping diagrams are [Mermaid](https://mermaid.js.org)
code blocks, which the renderers below draw, and which stay readable as text where they do not.

## Format

The report keeps to the part of Markdown that GitHub, GitLab, MkDocs (Material) and Docusaurus read
the same way:

* ATX headings in order: the title (`#`), a chapter each (`##`), and the groups and objects of a
  chapter (`###`), such as a risk category, a technical asset or a communication link.
* A table of contents that links to the chapters, and links from each mention of a risk category,
  asset, trust boundary, shared runtime or communication link to its heading. A risk links to the
  heading of its category, where its row in the table of findings has its details.
* Pipe tables, lists, and the paragraphs of a list item indented by four spaces, which
  Python-Markdown requires and CommonMark accepts.
* Severities, statuses and data breach probabilities as text, often in bold, never as colour only.
* No HTML at all.

The links to headings use the anchors that GitHub gives them: the heading in lower case, without
punctuation, with its spaces as hyphens, and `-1`, `-2` and so on appended when a heading repeats,
as communication links of the same title do. Docusaurus makes the same anchors. GitLab and MkDocs
differ in a few cases, so there a link to a heading of a model object can miss:

* GitLab turns runs of hyphens into one, so a title such as `A - B` gets `a-b` rather than `a---b`.
* MkDocs appends `_1` rather than `-1` to a repeated heading, and its default slugify drops letters
  that are not ASCII. `pymdownx.slugs.slugify` keeps them:

  ```yaml
  markdown_extensions:
    - toc:
        slugify: !!python/object/apply:pymdownx.slugs.slugify
          kwds:
            case: lower
  ```

The links of the table of contents, whose chapter titles are plain words, work everywhere.

## Diagrams

### Data-flow diagram

The data-flow diagram is a `flowchart`, top to bottom, or left to right with
`diagram_tweak_layout_left_right`:

| Model                                  | Mermaid                                | As in the PNG diagram |
| -------------------------------------- | -------------------------------------- | --------------------- |
| external entity                        | box, `id["Title"]`                     | box                   |
| process                                | stadium, `id(["Title"])`               | ellipse               |
| datastore                              | cylinder, `id[("Title")]`              | cylinder              |
| client used by a human (of any type)   | hexagon, `id{{"Title"}}`               | octagon               |
| asset out of scope                     | dashed border, class `outOfScope`      | dotted border         |
| trust boundary                         | `subgraph`, nested as in the model, titled `Title (type)` | cluster |
| communication link                     | `source -->\|"protocol"\| target`      | arrow                 |
| link that also receives data back      | thick arrow, `source ==>\|"protocol"\| target` | double hollow arrowhead at the initiator |

An arrow always points from the asset that initiates the communication link to its target, and is
labelled with the protocol, unless `diagram_tweak_suppress_edge_labels` is set. A link that sends
data and also receives data back is a thick arrow rather than one with heads at both ends, which
Mermaid only draws the same at either end, so that the initiator stays recognisable. A trust boundary
with no asset inside, not even in the boundaries nested in it, is left out, as in the PNG diagram.

### Data mapping

The data mapping is a table of each data asset with its data breach probability still at risk and
the technical assets that store and that process it, followed by a smaller diagram, `flowchart LR`,
of the storage only: an arrow from each data asset (a stadium) to each technical asset that stores it
(a box). Drawing where data is processed as well gives the example model over 50 edges, which
Mermaid's layout, unlike Graphviz, cannot bundle, and which cross beyond reading; the table has them
all.

### Ids and labels

Node and subgraph ids are generated: a prefix for the kind (`ta_` for a technical asset, `da_` for
a data asset, `tb_` for a trust boundary) and the hash of the id in the model, which the DOT files use
too, with a suffix in the rare case that two ids share a hash. They hold only letters, digits and
underscores, whatever the model holds, and stay the same as long as the model id does. Labels are the titles in double quotes, on one line, with `"`, `#`, `;`,
`` ` ``, `<`, `>`, `&` and `|` written as Mermaid entity codes (`#quot;`, `#35;` and so on), so that a
title can end neither its label, its statement, nor its code block, and becomes no HTML.

The syntax keeps to long-standing flowchart features: quoted labels, the classic node shapes,
subgraphs with an id and a title, `classDef` and `class`. The diagrams are not rendered when
threagile is built or tested; tests check them against that part of Mermaid's grammar instead.

## Renderers

| Renderer          | Mermaid                                                          | Notes |
| ----------------- | ---------------------------------------------------------------- | ----- |
| GitHub            | built in                                                         | Renders Markdown files in repositories, wikis and pages. |
| GitLab            | built in                                                         | See the anchors above. |
| MkDocs Material   | with `pymdownx.superfences` and a custom `mermaid` fence, below | See the anchors above. |
| Docusaurus        | with `@docusaurus/theme-mermaid` and `markdown: {mermaid: true}` | Reads `.md` as MDX by default, which the report is written for. |
| others            | not drawn                                                        | The diagram shows as a code block. |

MkDocs Material draws Mermaid with this in `mkdocs.yml`:

```yaml
markdown_extensions:
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
```

A site that runs Markdown through a template engine first, such as the `mkdocs-macros` plugin,
reads the `{{` of the hexagons as a template; leave the report out of it with the plugin's settings.

## Model text

Model text is untrusted, and the report may end up on a site that renders the HTML in Markdown,
which GitHub strips but MkDocs and Docusaurus keep. So everything from the model is escaped where it
lands, in headings, table cells, lists, links and emphasis alike:

* `<`, `>` and `&` are written as character references, so no HTML gets through; a backtick, `*`,
  `_` (unless between two letters or digits), `[`, `]`, `#` and `\` are escaped with a backslash, so
  model text starts no code, emphasis or link. `|`, `~` and `$` are character references, so text
  ends no table cell, strikes nothing through and starts no math.
* `{` and `}` are escaped, as are `import` and `export` at the start of a paragraph, which Docusaurus
  would read as MDX expressions and modules and run; the braces would also be MkDocs attribute lists.
* Line breaks become spaces, and a paragraph or list item that would start a list, a heading, a
  quote, an admonition or a thematic break gets its first character escaped.
* Ids, the risk ids among them, are code spans, or escaped text when they hold a backtick or a pipe.

Of the markup that rule and model texts use, `<b>` becomes bold, `<i>` and `<u>` italics (Markdown
has no underline) and `<br>` a new paragraph, or a space where the text has to stay on one line, as
in a table cell; tags are closed and nested properly, as in the HTML report. `<a href="...">` becomes a link only when the
address is `http` or `https`, and so do the links to cheat sheets and homepages; their addresses are
percent-encoded where Markdown would read them otherwise.

With [`SOURCE_DATE_EPOCH`](./mode-analyze.md#reproducible-reports) set, the file is the same on every
run, which keeps its diffs to what changed in the model.
