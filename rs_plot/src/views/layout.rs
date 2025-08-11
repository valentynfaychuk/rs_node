pub fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; }}
    th {{ text-align: left; background: #f5f5f5; position: sticky; top: 0; }}
    tbody tr:nth-child(even) {{ background: #fafafa; }}
    .pill {{ padding: 2px 8px; border-radius: 999px; border: 1px solid #ddd; font-size: 12px; }}
    .muted {{ color:#666 }}
    nav a {{ margin-right: 12px; }}
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/entries">Entries</a>
    <a href="/peers">Peers</a>
  </nav>
  {}
</body>
</html>
"#,
        html_escape(title),
        body
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
