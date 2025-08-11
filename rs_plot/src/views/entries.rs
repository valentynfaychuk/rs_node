use crate::models::Entry;

pub fn page(entries: &[Entry]) -> String {
    let mut rows = String::new();
    for e in entries {
        use std::fmt::Write;
        let _ = write!(
            rows,
            "<tr><td><a href=\"/entries/{}\">{}</a></td>\
           <td>{}</td><td><span class=\"pill\">{}</span></td>\
           <td class=\"muted\">{}</td></tr>",
            esc(&e.id),
            esc(&e.id),
            esc(&e.author),
            esc(&e.kind),
            e.ts_ms
        );
    }
    format!(
        r#"
<h1>Entries</h1>
<table>
  <thead>
    <tr><th>ID</th><th>Author</th><th>Kind</th><th>Timestamp</th></tr>
  </thead>
  <tbody>{}</tbody>
</table>
"#,
        rows
    )
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
