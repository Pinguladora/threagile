# Analyze model

The output of running tool may be in different formats:

* `report.pdf` - most comprehensive report contained all information.
* `risks.xlsx` and `risks.json` - list of identified risks in Excel and JSON formats.
* `data-asset-diagram.png` - image/dot file which contains all data assets and relationship between them.
* `data-flow-diagram.png` - image/dot file which contains all technical assets and relationship between them.
* `stats.json` - contains statistics of identified risks.
* [adocReport](./docs/asciidoctor-report.md)

## Reproducible reports

The same model always produces the same diagrams, JSON, Excel and AsciiDoc files.
The only thing that changes between runs is the timestamp the reports are stamped
with (the report date when the model has no `date`, and the execution timestamp).
Set [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/)
to a Unix timestamp to fix it, for example to the time of the last commit:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) threagile analyze-model --model threagile.yaml --output out
```

All outputs are then byte-identical between runs, except `report.pdf`: the PDF
library numbers the objects of the imported background page in random order, so
the PDF bytes differ while its content stays the same.
