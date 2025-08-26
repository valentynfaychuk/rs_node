use crate::state::Metrics;

pub fn page(metrics: &Metrics) -> String {
    let uptime_formatted = format_uptime(metrics.uptime_seconds);
    let bytes_formatted = format_bytes(metrics.total_bytes_received);
    let bytes_per_sec_formatted = format_bytes(metrics.bytes_per_second as u64);
    let active_peer_percentage = if metrics.total_peers > 0 {
        (metrics.active_peers as f64 / metrics.total_peers as f64 * 100.0) as u32
    } else {
        0
    };
    
    format!(
        r#"
<div class="dashboard">
  <!-- Header -->
  <div class="dashboard-header">
    <div class="header-content">
      <div class="header-title">
        <h1>Node Metrics Dashboard</h1>
        <p>Real-time blockchain node monitoring</p>
      </div>
      <div class="status-indicator">
        <div class="status-dot"></div>
        <span>Live</span>
      </div>
    </div>
  </div>

  <!-- Primary Metrics -->
  <div class="metrics-grid">
    <div class="metric-card primary">
      <div class="card-header">
        <div class="card-icon network">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
          </svg>
        </div>
        <h3>Throughput</h3>
      </div>
      <div class="card-content">
        <div class="metric-value" id="messages-per-second">{:.2}</div>
        <div class="metric-subtitle">Messages per second</div>
        <div class="trend-indicator positive">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
            <polyline points="17 6 23 6 23 12"/>
          </svg>
          +5.2%
        </div>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-header">
        <div class="card-icon data">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
            <line x1="12" y1="22.08" x2="12" y2="12"/>
          </svg>
        </div>
        <h3>Data Transferred</h3>
      </div>
      <div class="card-content">
        <div class="metric-value" id="total-bytes">{}</div>
        <div class="metric-subtitle">Total network traffic</div>
        <div class="metric-secondary" id="bytes-per-second">{}/s current</div>
        <div class="metric-secondary" id="total-udp-packets">{} UDP packets total</div>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-header">
        <div class="card-icon blockchain">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7"/>
            <rect x="14" y="3" width="7" height="7"/>
            <rect x="14" y="14" width="7" height="7"/>
            <rect x="3" y="14" width="7" height="7"/>
          </svg>
        </div>
        <h3>Blockchain Entries</h3>
      </div>
      <div class="card-content">
        <div class="metric-value" id="total-entries">{}</div>
        <div class="metric-subtitle">Total entries processed</div>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-header">
        <div class="card-icon uptime">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
        </div>
        <h3>System Uptime</h3>
      </div>
      <div class="card-content">
        <div class="metric-value" id="uptime">{}</div>
        <div class="metric-subtitle">Node operational time</div>
      </div>
    </div>
  </div>

  <!-- Secondary Metrics -->
  <div class="secondary-metrics">
    <div class="peer-card">
      <div class="card-header">
        <div class="card-icon peers">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
        </div>
        <h3>Peer Network</h3>
      </div>
      <div class="card-content">
        <div class="peer-stats">
          <div class="peer-main">
            <span class="metric-value" id="active-peers">{}</span>
            <span class="peer-total">of <span id="total-peers">{}</span></span>
          </div>
          <div class="peer-progress">
            <div class="progress-bar">
              <div class="progress-fill" style="width: {}%"></div>
            </div>
            <div class="progress-label">Active connections</div>
          </div>
          <div class="peer-badges">
            <div class="badge active">
              <span id="active-peers-badge">{}</span> Active
            </div>
            <div class="badge total">
              <span id="total-peers-badge">{}</span> Total
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-header">
        <div class="card-icon messages">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M8 2v4"/>
            <path d="M16 2v4"/>
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
            <path d="M3 10h18"/>
          </svg>
        </div>
        <h3>Total Messages</h3>
      </div>
      <div class="card-content">
        <div class="metric-value" id="total-messages">{}</div>
        <div class="metric-subtitle">Messages processed</div>
      </div>
    </div>

    <div class="protocol-breakdown-card">
      <div class="card-header">
        <div class="card-icon protocol">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/>
            <path d="M2 17l10 5 10-5"/>
            <path d="M2 12l10 5 10-5"/>
          </svg>
        </div>
        <h3>Protocol Breakdown</h3>
      </div>
      <div class="card-content">
        <div class="protocol-stats">
          <div class="protocol-row">
            <span class="protocol-type">Ping:</span>
            <span class="protocol-count" id="ping-count">0</span>
          </div>
          <div class="protocol-row">
            <span class="protocol-type">Pong:</span>
            <span class="protocol-count" id="pong-count">0</span>
          </div>
          <div class="protocol-row">
            <span class="protocol-type">Entries:</span>
            <span class="protocol-count" id="entry-count">0</span>
          </div>
          <div class="protocol-row">
            <span class="protocol-type">Attestations:</span>
            <span class="protocol-count" id="attestation-count">0</span>
          </div>
          <div class="protocol-row">
            <span class="protocol-type">TxPool:</span>
            <span class="protocol-count" id="txpool-count">0</span>
          </div>
          <div class="protocol-row error-row">
            <span class="protocol-type">Errors:</span>
            <span class="protocol-count error-count" id="total-errors">0</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
* {{
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}}

body {{
  background: #0a0a0a;
  color: #ffffff;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.5;
}}

.dashboard {{
  min-height: 100vh;
  padding: 24px;
  background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
}}

.dashboard-header {{
  margin-bottom: 32px;
}}

.header-content {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1400px;
  margin: 0 auto;
}}

.header-title h1 {{
  font-size: 2.5rem;
  font-weight: 700;
  background: linear-gradient(135deg, #00ff88, #00ccff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 8px;
}}

.header-title p {{
  color: #888;
  font-size: 1.1rem;
}}

.status-indicator {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: rgba(0, 255, 136, 0.1);
  border: 1px solid rgba(0, 255, 136, 0.2);
  border-radius: 20px;
  color: #00ff88;
  font-weight: 500;
}}

.status-dot {{
  width: 8px;
  height: 8px;
  background: #00ff88;
  border-radius: 50%;
  animation: pulse 2s infinite;
}}

@keyframes pulse {{
  0%, 100% {{ opacity: 1; }}
  50% {{ opacity: 0.5; }}
}}

.metrics-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
  max-width: 1400px;
  margin-left: auto;
  margin-right: auto;
}}

.secondary-metrics {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  gap: 24px;
  max-width: 1400px;
  margin: 0 auto;
}}

.metric-card, .peer-card, .health-card, .protocol-breakdown-card {{
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 16px;
  padding: 24px;
  backdrop-filter: blur(10px);
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}}

.metric-card::before, .peer-card::before, .health-card::before, .protocol-breakdown-card::before {{
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
}}

.metric-card:hover, .peer-card:hover, .health-card:hover, .protocol-breakdown-card:hover {{
  transform: translateY(-4px);
  border-color: rgba(0, 255, 136, 0.3);
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
}}

.metric-card.primary {{
  border-color: rgba(0, 255, 136, 0.3);
  background: rgba(0, 255, 136, 0.05);
}}

.card-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 20px;
}}

.card-icon {{
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
}}

.card-icon.network {{ background: rgba(0, 255, 136, 0.15); color: #00ff88; }}
.card-icon.data {{ background: rgba(0, 204, 255, 0.15); color: #00ccff; }}
.card-icon.blockchain {{ background: rgba(255, 106, 0, 0.15); color: #ff6a00; }}
.card-icon.uptime {{ background: rgba(138, 43, 226, 0.15); color: #8a2be2; }}
.card-icon.peers {{ background: rgba(255, 20, 147, 0.15); color: #ff1493; }}
.card-icon.messages {{ background: rgba(50, 205, 50, 0.15); color: #32cd32; }}
.card-icon.health {{ background: rgba(255, 215, 0, 0.15); color: #ffd700; }}
.card-icon.protocol {{ background: rgba(138, 43, 226, 0.15); color: #8a2be2; }}

.card-header h3 {{
  font-size: 1rem;
  font-weight: 600;
  color: #ccc;
}}

.card-content {{
  display: flex;
  flex-direction: column;
  gap: 8px;
}}

.metric-value {{
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  font-family: 'SF Mono', Monaco, monospace;
}}

.metric-subtitle {{
  color: #888;
  font-size: 0.9rem;
}}

.metric-secondary {{
  color: #aaa;
  font-size: 0.85rem;
  margin-top: 4px;
}}

.trend-indicator {{
  display: flex;
  align-items: center;
  gap: 4px;
  margin-top: 8px;
  font-size: 0.85rem;
  font-weight: 600;
}}

.trend-indicator.positive {{
  color: #00ff88;
}}

.peer-stats {{
  display: flex;
  flex-direction: column;
  gap: 16px;
}}

.peer-main {{
  display: flex;
  align-items: baseline;
  gap: 8px;
}}

.peer-total {{
  color: #888;
  font-size: 1.1rem;
}}

.peer-progress, .health-progress {{
  display: flex;
  flex-direction: column;
  gap: 8px;
}}

.progress-bar {{
  width: 100%;
  height: 8px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  overflow: hidden;
}}

.progress-fill {{
  height: 100%;
  background: linear-gradient(90deg, #00ff88, #00ccff);
  border-radius: 4px;
  transition: width 0.3s ease;
}}

.health-fill {{
  background: linear-gradient(90deg, #00ff88, #32cd32);
}}

.progress-label {{
  color: #888;
  font-size: 0.8rem;
}}

.peer-badges {{
  display: flex;
  gap: 12px;
}}

.badge {{
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 0.8rem;
  font-weight: 600;
  text-align: center;
}}

.badge.active {{
  background: rgba(0, 255, 136, 0.15);
  color: #00ff88;
  border: 1px solid rgba(0, 255, 136, 0.3);
}}

.badge.total {{
  background: rgba(255, 255, 255, 0.05);
  color: #ccc;
  border: 1px solid rgba(255, 255, 255, 0.1);
}}

.health-status {{
  font-size: 2rem;
  font-weight: 700;
  color: #00ff88;
}}

.protocol-stats {{
  display: flex;
  flex-direction: column;
  gap: 12px;
}}

.protocol-row {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
}}

.protocol-row.error-row {{
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  margin-top: 8px;
  padding-top: 16px;
}}

.protocol-type {{
  color: #888;
  font-size: 0.9rem;
}}

.protocol-count {{
  color: #fff;
  font-weight: 600;
  font-family: 'SF Mono', Monaco, monospace;
}}

.protocol-count.error-count {{
  color: #ff6666;
}}

@media (max-width: 768px) {{
  .dashboard {{
    padding: 16px;
  }}
  
  .header-title h1 {{
    font-size: 2rem;
  }}
  
  .metrics-grid, .secondary-metrics {{
    grid-template-columns: 1fr;
  }}
  
  .metric-value {{
    font-size: 2rem;
  }}
  
  .header-content {{
    flex-direction: column;
    gap: 16px;
    align-items: flex-start;
  }}
}}
</style>

<script>
function formatBytes(bytes) {{
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}}

function formatUptime(seconds) {{
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  let parts = [];
  if (days > 0) parts.push(`${{days}}d`);
  if (hours > 0) parts.push(`${{hours}}h`);
  if (minutes > 0) parts.push(`${{minutes}}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${{secs}}s`);
  
  return parts.join(' ');
}}

async function fetchMetrics() {{
  try {{
    const response = await fetch('/metrics/json');
    const metrics = await response.json();
    
    // Update values
    document.getElementById('total-messages').textContent = metrics.total_messages.toLocaleString();
    document.getElementById('messages-per-second').textContent = metrics.messages_per_second.toFixed(1);
    document.getElementById('total-bytes').textContent = formatBytes(metrics.total_bytes_received);
    document.getElementById('bytes-per-second').textContent = formatBytes(metrics.bytes_per_second);
    document.getElementById('total-udp-packets').textContent = (metrics.total_udp_packets || 0).toLocaleString() + ' UDP packets total';
    document.getElementById('total-peers').textContent = metrics.total_peers.toLocaleString();
    document.getElementById('active-peers').textContent = metrics.active_peers.toLocaleString();
    document.getElementById('total-entries').textContent = metrics.total_entries.toLocaleString();
    document.getElementById('uptime').textContent = formatUptime(metrics.uptime_seconds);
    
    // Update badges
    document.getElementById('active-peers-badge').textContent = metrics.active_peers;
    document.getElementById('total-peers-badge').textContent = metrics.total_peers;
    
    // Update progress bar
    const activePercentage = metrics.total_peers > 0 ? (metrics.active_peers / metrics.total_peers * 100) : 0;
    const progressFill = document.querySelector('.peer-progress .progress-fill');
    if (progressFill) {{
      progressFill.style.width = activePercentage.toFixed(1) + '%';
    }}
    
    // Update protocol breakdown
    document.getElementById('ping-count').textContent = (metrics.ping_count || 0).toLocaleString();
    document.getElementById('pong-count').textContent = (metrics.pong_count || 0).toLocaleString();
    document.getElementById('entry-count').textContent = (metrics.entry_count || 0).toLocaleString();
    document.getElementById('attestation-count').textContent = (metrics.attestation_bulk_count || 0).toLocaleString();
    document.getElementById('txpool-count').textContent = (metrics.txpool_count || 0).toLocaleString();
    document.getElementById('total-errors').textContent = (metrics.total_errors || 0).toLocaleString();
  }} catch (e) {{
    console.error('Failed to fetch metrics:', e);
  }}
}}

// fetch metrics every 5 seconds
setInterval(fetchMetrics, 5000);

// initial fetch after page load
fetchMetrics();
</script>
"#,
        metrics.messages_per_second,
        bytes_formatted,
        bytes_per_sec_formatted,
        metrics.total_udp_packets,
        metrics.total_entries,
        uptime_formatted,
        metrics.active_peers,
        metrics.total_peers,
        active_peer_percentage,
        metrics.active_peers,
        metrics.total_peers,
        metrics.total_messages,
    )
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let k = 1024_f64;
    let i = (bytes as f64).log(k).floor() as usize;
    let i = i.min(UNITS.len() - 1);
    let size = bytes as f64 / k.powi(i as i32);
    format!("{:.1} {}", size, UNITS[i])
}

fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{}s", secs));
    }
    
    parts.join(" ")
}