use crate::state::PeerInfo;
use std::collections::HashMap;
use std::net::SocketAddr;

pub fn page(peers: &HashMap<SocketAddr, PeerInfo>) -> String {
    let rows = rows(peers);
    format!(
        r#"
<h1>Peers</h1>
<table>
  <thead>
    <tr><th>ID</th><th>Address</th><th>Role</th><th>Last msg</th><th>Seen (ms)</th><th>SK</th></tr>
  </thead>
  <tbody id="peer-tbody">
    {rows}
  </tbody>
</table>
<script>
const tbody = document.getElementById('peer-tbody');
const es = new EventSource('/peers/stream');

es.onmessage = (evt) => {{
  try {{
    const peers = JSON.parse(evt.data);
    let html = '';
    for (const p of peers) {{
      html += `<tr>
        <td>${{esc(p.id ?? '')}}</td>
        <td>${{esc(p.addr ?? '')}}</td>
        <td><span class="pill">${{esc(p.kind ?? '')}}</span></td>
        <td>${{esc(p.last_msg ?? '')}}</td>
        <td>${{Number(p.last_seen_ms ?? 0).toString()}}</td>
        <td><span class="muted">${{esc(p.sk ?? '')}}</span></td>
      </tr>`;
    }}
    tbody.innerHTML = html;
  }} catch (e) {{
    console.error('bad peers payload', e);
  }}
}};

function esc(s) {{
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}}
</script>
"#,
    )
}

pub fn rows(peers: &HashMap<SocketAddr, PeerInfo>) -> String {
    // snapshot & sort newest first

    let mut v: Vec<&PeerInfo> = peers.values().collect();
    v.sort_by(|a, b| a.sk.as_deref().cmp(&b.sk.as_deref()));

    let mut s = String::with_capacity(v.len() * 96);
    for p in v {
        use std::fmt::Write;
        let _ = write!(
            s,
            "<tr>\
               <td>{}</td>\
               <td>{}</td>\
               <td><span class=\"pill\"></span></td>\
               <td>{}</td>\
               <td>{}</td>\
               <td><span class=\"muted\"></span></td>\
             </tr>",
            esc_opt(&p.sk),
            esc(&p.addr.to_string()),
            esc_opt(&p.last_msg),
            p.last_seen_ms,
        );
    }
    s
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn esc_opt(s: &Option<String>) -> String {
    s.as_deref().map(esc).unwrap_or_default()
}
