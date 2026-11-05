// The PDF report of Threagile. It lays out the report data that threagile writes to data.json: the chapters of the
// Markdown report as blocks of plain text. Text from the data is always shown as a string, never read as markup.

#let data = json("data.json")
#let labels = data.blocks.filter(block => block.kind == "heading").map(block => block.label)
// the columns whose cells name a severity or a status, which show in the colour of their level
#let levelColumns = ("Severity", "Status", "Severity in the baseline")

#set document(title: data.title, author: data.author, keywords: ("threat model", "Threagile"))
#set text(font: "DejaVu Sans", size: 9.5pt, lang: "en")
#set par(justify: false, leading: 0.6em)
#set heading(numbering: "1.1")
#set table(stroke: 0.5pt + luma(190), inset: 4pt)
#show table: set text(size: 8pt)
#show raw: set text(font: "DejaVu Sans Mono", size: 0.95em)
#show link: set text(fill: rgb(data.colors.at("link")))
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  it
}

#let render-span(span) = {
  if span.at("break", default: false) {
    return linebreak()
  }
  let body = if span.at("code", default: false) { raw(span.at("text", default: "")) } else { [#span.at("text", default: "")] }
  if span.at("bold", default: false) {
    body = strong(body)
  }
  if span.at("italic", default: false) {
    body = emph(body)
  }
  if "link" in span {
    body = link(span.link, body)
  } else if "ref" in span and span.ref in labels {
    body = link(label(span.ref), body)
  }
  body
}

#let render-spans(spans) = spans.map(render-span).join()

#let plain(spans) = spans.map(span => span.at("text", default: "")).join(default: "")

// render-cell shows a table cell, in the colour of its level when its column names levels
#let render-cell(column, content) = {
  let text-of-cell = plain(content)
  if column.title in levelColumns and text-of-cell in data.colors {
    text(fill: rgb(data.colors.at(text-of-cell)), weight: "bold", render-spans(content))
  } else {
    render-spans(content)
  }
}

#let render-block(block) = {
  if block.kind == "heading" {
    [#heading(level: block.level, render-spans(block.at("spans", default: ())))#label(block.label)]
  } else if block.kind == "paragraph" {
    par(render-spans(block.at("spans", default: ())))
  } else if block.kind == "list" {
    let items = block.at("items", default: ()).map(item => item.map(render-block).join())
    if block.at("ordered", default: false) { enum(..items) } else { list(..items) }
  } else if block.kind == "table" {
    let columns = block.at("columns", default: ())
    table(
      columns: columns.len(),
      align: columns.map(column => if column.at("number", default: false) { right } else { left }),
      table.header(..columns.map(column => strong(column.title))),
      ..block.at("rows", default: ()).map(row => row.enumerate().map(((index, content)) => render-cell(columns.at(index), content))).flatten(),
    )
  } else if block.kind == "image" {
    // a diagram is wide: it gets a page of its own, turned to landscape
    page(flipped: true, figure(image(block.image, width: 100%, height: 1fr, fit: "contain", alt: block.alt), caption: block.alt))
  }
}

#page(numbering: none)[
  #v(3cm)
  #if "logo" in data {
    image(data.logo, width: 6cm, alt: "Logo")
    v(1cm)
  }
  #text(size: 26pt, weight: "bold", data.title)
  #v(0.5cm)
  #text(size: 14pt, data.subtitle)
  #v(2cm)
  #grid(
    columns: 2,
    column-gutter: 1.5em,
    row-gutter: 0.8em,
    [Author], [#data.author],
    ..if data.at("contributors", default: ()).len() > 0 { ([Contributors], [#data.contributors.join(", ")]) },
    [Date], [#data.date],
    [Threagile version], [#data.version],
  )
]

#set page(
  numbering: "1",
  header: context [
    #set text(size: 7.5pt, fill: luma(90))
    #data.title #h(1fr) Threat Model Report
  ],
)
#counter(page).update(1)

#outline(depth: 2)

#for item in data.blocks {
  render-block(item)
}
