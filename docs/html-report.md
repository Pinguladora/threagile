# HTML report

`analyze-model` writes the report as `report.html` as well (see [analyze mode](./mode-analyze.md)):
one HTML page with the content of the PDF report, from the management summary to the risk rules
checked. `--report-html` names the file and `--skip-report-html` skips it; the config keys are
`ReportHTMLFilename` and `SkipReportHTML`. `ReportConfiguration.HideChapter` hides the
`AssetRegister` and `RiskRulesCheckedByThreagile` chapters as in the PDF report, and chapters the
model has nothing for, such as questions or abuse cases, are left out.

The page needs nothing else, so it works offline and as a CI artifact:

* The style sheet is inline, and the data-flow and data mapping diagrams are inline SVG, rendered
  by Graphviz from the same source as the PNG images. They scale to the width of the page; zoom in
  for the details.
* It runs no script and loads nothing: no fonts, images or other files. Its content security
  policy, in a `<meta>` element, allows only its own style sheet by its hash. A server that sets
  its own policy for the page has to allow that hash as well (`style-src 'sha256-...'`, see the
  page source).
* It has a light and a dark colour scheme, follows the system setting, prints well and fits a
  phone screen, where wide tables scroll on their own.

Everything from the model is shown as text. Of the markup that rule and model texts use, only
`<b>`, `<i>`, `<u>` and `<br>`, written exactly so, become formatting, and `<a href="...">` a link
when the address is `http` or `https`. Links to cheat sheets and homepages are kept only for
`http` and `https` too.

With [`SOURCE_DATE_EPOCH`](./mode-analyze.md#reproducible-reports) set, the page is the same on
every run.
