use crate::models::Entry;

pub fn page(e: &Entry) -> String {
    format!(
        r#"
<h1>Entry {}</h1>
<p><b>Author:</b> {}<br/>
<b>Kind:</b> {}<br/>
<b>Timestamp:</b> {} ms</p>
<hr/>
<p>{}</p>
"#,
        esc(&e.id),
        esc(&e.author),
        esc(&e.kind),
        e.ts_ms,
        esc(&e.summary)
    )
}
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
