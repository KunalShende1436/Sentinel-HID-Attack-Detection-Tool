/* ═══════════════════════════════════════════════════════════════════════════
   SENTINEL — HID Attack Detection Dashboard
   Frontend Application (Vanilla JS)
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

class SentinelApp {
  constructor() {
    /** @type {SocketIOClient.Socket|null} */
    this.socket = null;

    /** @type {Array<Object>} In-memory alert store */
    this.alerts = [];

    /** @type {Object} Running statistics counters */
    this.stats = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      killed: 0,
      snapshots: 0,
    };

    /** @type {Array<{timestamp:number, severity:number}>} Timeline chart data */
    this.chartData = [];

    /** @type {boolean} Whether the backend engine is running */
    this.isRunning = false;

    /** @type {number} Maximum alerts to keep in memory */
    this.maxAlerts = 500;

    /** @type {number} Maximum chart data points */
    this.maxChartPoints = 300;

    /** @type {HTMLCanvasElement|null} */
    this.canvas = null;

    /** @type {CanvasRenderingContext2D|null} */
    this.ctx = null;

    // Boot
    this.init();
  }

  /* ═══════════════════════════════════════════════════════════════════════
     INITIALIZATION
     ═══════════════════════════════════════════════════════════════════════ */

  init() {
    this.connectSocket();
    this.startClock();
    this.initChart();
    this.fetchInitialData();
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SOCKET.IO CONNECTION
     ═══════════════════════════════════════════════════════════════════════ */

  connectSocket() {
    // Guard: if Socket.IO CDN failed to load, fall back to REST polling
    if (typeof io === 'undefined') {
      console.warn('[Sentinel] Socket.IO not loaded — falling back to REST polling.');
      this._pollInterval = setInterval(() => this.fetchInitialData(), 3000);
      return;
    }

    // Connect to the same host that served the page (default namespace)
    this.socket = io();

    this.socket.on('connect', () => {
      this.showToast('Connected to Sentinel', 'info');
      console.log('[Sentinel] Socket connected:', this.socket.id);
    });

    this.socket.on('disconnect', (reason) => {
      this.showToast('Disconnected from Sentinel', 'critical');
      console.warn('[Sentinel] Socket disconnected:', reason);

      // Reflect offline state in UI
      this.updateStatusUI(false);
    });

    this.socket.on('connect_error', (err) => {
      console.error('[Sentinel] Socket connection error:', err.message);
    });

    // Real-time alert stream
    this.socket.on('alert', (data) => {
      this.handleAlert(data);
    });

    // Periodic status updates (every ~2s from backend)
    this.socket.on('status', (data) => {
      this.updateStatus(data);
    });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     ALERT HANDLING
     ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Process an incoming real-time alert.
   * @param {Object} alert - Alert JSON from the backend.
   */
  handleAlert(alert) {
    // Store (newest first)
    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxAlerts) {
      this.alerts.pop();
    }

    // Update statistics
    this.stats.total++;
    const sevName = this.getSeverityName(alert.severity).toLowerCase();
    if (this.stats[sevName] !== undefined) {
      this.stats[sevName]++;
    }
    if (alert.details && alert.details.process_killed) {
      this.stats.killed++;
    }
    if (alert.snapshot_requested) {
      this.stats.snapshots++;
    }

    // Add to chart timeline
    this.chartData.push({
      timestamp: alert.timestamp * 1000,
      severity: alert.severity,
    });
    if (this.chartData.length > this.maxChartPoints) {
      this.chartData.shift();
    }

    // Update all UI sections
    this.renderAlert(alert, true);
    this.updateStats();
    this.drawChart();
    this.updateGauge();

    // If a snapshot was captured, refresh snapshot list after a delay
    if (alert.snapshot_requested) {
      setTimeout(() => this.fetchSnapshots(), 2000);
    }

    // Show toast for HIGH severity and above
    if (alert.severity >= 75) {
      this.showToast(
        `${this.getSeverityName(alert.severity).toUpperCase()}: ${alert.title}`,
        sevName
      );
    }
  }

  /**
   * Render a single alert card into the feed.
   * @param {Object} alert - Alert data.
   * @param {boolean} prepend - If true, insert at top; otherwise append.
   */
  renderAlert(alert, prepend = false) {
    // Hide empty state
    const empty = document.getElementById('alert-empty');
    if (empty) {
      empty.style.display = 'none';
    }

    const feed = document.getElementById('alert-feed-body');
    const el = document.createElement('div');
    const sevName = this.getSeverityName(alert.severity).toLowerCase();
    el.className = `alert-item severity-${sevName}`;

    // Format timestamp
    const time = new Date(alert.timestamp * 1000);
    const timeStr = time.toLocaleTimeString('en-US', { hour12: false });

    // Build tags
    let tags = '';
    if (alert.details && alert.details.process_killed) {
      tags += '<span class="alert-tag killed">⚡ KILLED</span>';
    }
    if (alert.snapshot_requested) {
      tags += '<span class="alert-tag snapshot">📸 SNAPSHOT</span>';
    }

    // Truncate details for display
    const detailsStr = JSON.stringify(alert.details || {});
    const truncated =
      detailsStr.length > 150
        ? detailsStr.substring(0, 150) + '...'
        : detailsStr;

    const displaySeverity = (
      alert.severity_name || sevName
    ).toUpperCase();

    el.innerHTML = `
      <div class="alert-header">
        <span class="alert-severity-badge severity-bg-${sevName}">${this.escapeHtml(displaySeverity)}</span>
        <span class="alert-timestamp">${timeStr}</span>
      </div>
      <div class="alert-title">${this.escapeHtml(alert.title)}</div>
      <div class="alert-details">${this.escapeHtml(truncated)}</div>
      ${tags ? `<div class="alert-tags">${tags}</div>` : ''}
    `;

    if (prepend) {
      feed.insertBefore(el, feed.firstChild);
    } else {
      feed.appendChild(el);
    }

    // Update count label
    document.getElementById('alert-count').textContent =
      `${this.alerts.length} alert${this.alerts.length !== 1 ? 's' : ''}`;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     STATUS MANAGEMENT
     ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Update all status-related UI from a status payload.
   * @param {Object} data - Status JSON from the backend.
   */
  updateStatus(data) {
    this.isRunning = data.running;
    this.updateStatusUI(data.running);

    // Button states
    document.getElementById('btn-start').disabled = data.running;
    document.getElementById('btn-stop').disabled = !data.running;

    // Alert engine module
    if (data.engine !== undefined) {
      const engineEl = document.getElementById('module-alert_engine');
      if (engineEl) {
        engineEl.className = `module-pill ${data.engine ? 'online' : 'offline'}`;
      }
    }

    // Detector modules
    if (data.detectors) {
      for (const [name, running] of Object.entries(data.detectors)) {
        const el = document.getElementById(`module-${name}`);
        if (el) {
          el.className = `module-pill ${running ? 'online' : 'offline'}`;
        }
      }
    }
  }

  /**
   * Update the header status badge.
   * @param {boolean} running
   */
  updateStatusUI(running) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (running) {
      dot.className = 'status-dot active pulse-green';
      text.textContent = 'ACTIVE';
      text.style.color = 'var(--success)';
    } else {
      dot.className = 'status-dot inactive';
      text.textContent = 'OFFLINE';
      text.style.color = 'var(--danger)';
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     TIMELINE CHART (Canvas 2D)
     ═══════════════════════════════════════════════════════════════════════ */

  initChart() {
    this.canvas = document.getElementById('timeline-chart');
    this.ctx = this.canvas.getContext('2d');
    this.resizeChart();
    window.addEventListener('resize', () => this.resizeChart());
    this.drawChart();
  }

  resizeChart() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const cssWidth = rect.width - 40; // account for parent padding
    const cssHeight = 120;

    // Set display size
    this.canvas.style.width = cssWidth + 'px';
    this.canvas.style.height = cssHeight + 'px';

    // Set actual size in memory (scaled for retina)
    this.canvas.width = Math.floor(cssWidth * dpr);
    this.canvas.height = Math.floor(cssHeight * dpr);

    // Scale context to match
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    this.drawChart();
  }

  drawChart() {
    if (!this.ctx) return;

    const ctx = this.ctx;
    const w = this.canvas.width / (window.devicePixelRatio || 1);
    const h = this.canvas.height / (window.devicePixelRatio || 1);

    ctx.clearRect(0, 0, w, h);

    // Empty state
    if (this.chartData.length === 0) {
      ctx.fillStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Waiting for alert data...', w / 2, h / 2);
      return;
    }

    // 5-minute window, 60 buckets (5 seconds each)
    const now = Date.now();
    const windowMs = 5 * 60 * 1000;
    const bucketCount = 60;
    const bucketMs = windowMs / bucketCount;
    const buckets = new Array(bucketCount).fill(0);

    for (const point of this.chartData) {
      const age = now - point.timestamp;
      if (age > windowMs || age < 0) continue;
      const idx = Math.floor((windowMs - age) / bucketMs);
      if (idx >= 0 && idx < bucketCount) {
        buckets[idx] = Math.max(buckets[idx], point.severity);
      }
    }

    const padding = 10;
    const barWidth = (w - padding * 2) / bucketCount;
    const maxH = h - 20;

    // Draw bars
    for (let i = 0; i < bucketCount; i++) {
      const val = buckets[i];
      if (val === 0) continue;

      const barH = (val / 100) * maxH;
      const x = padding + i * barWidth;
      const y = h - padding - barH;

      ctx.fillStyle = this.getSeverityColor(val);
      ctx.globalAlpha = 0.8;

      // Rounded top corners
      const r = Math.min(2, (barWidth - 2) / 2);
      const bw = barWidth - 2;
      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + bw - r, y);
      ctx.arcTo(x + bw, y, x + bw, y + r, r);
      ctx.lineTo(x + bw, y + barH);
      ctx.lineTo(x, y + barH);
      ctx.lineTo(x, y + r);
      ctx.arcTo(x, y, x + r, y, r);
      ctx.closePath();
      ctx.fill();

      ctx.globalAlpha = 1;
    }

    // Draw baseline
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(padding, h - padding);
    ctx.lineTo(w - padding, h - padding);
    ctx.stroke();

    // Time axis labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.3)';
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('-5m', padding + 10, h - 1);
    ctx.fillText('-2.5m', w / 2, h - 1);
    ctx.fillText('now', w - padding - 10, h - 1);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     THREAT GAUGE (SVG Arc)
     ═══════════════════════════════════════════════════════════════════════ */

  updateGauge() {
    // Threat level = max severity among alerts in the last 60 seconds
    const now = Date.now();
    const cutoff = now - 60000;
    let maxSev = 0;

    for (const a of this.alerts) {
      if (a.timestamp * 1000 < cutoff) break; // alerts are newest-first
      if (a.severity > maxSev) maxSev = a.severity;
    }

    const arc = document.getElementById('gauge-arc');
    const label = document.getElementById('gauge-value');

    if (!arc || !label) return;

    const totalLen = 173; // approximate arc length
    const dashLen = (maxSev / 100) * totalLen;

    arc.setAttribute('stroke-dasharray', `${dashLen} ${totalLen}`);
    arc.setAttribute('stroke', this.getSeverityColor(maxSev));

    label.textContent = maxSev;
    label.style.color = this.getSeverityColor(maxSev);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     STATS DISPLAY
     ═══════════════════════════════════════════════════════════════════════ */

  updateStats() {
    const ids = {
      'stat-total': this.stats.total,
      'stat-critical': this.stats.critical,
      'stat-high': this.stats.high,
      'stat-medium': this.stats.medium,
      'stat-low': this.stats.low + this.stats.info,
      'stat-killed': this.stats.killed,
      'stat-snapshots': this.stats.snapshots,
    };

    for (const [id, value] of Object.entries(ids)) {
      const el = document.getElementById(id);
      if (el) {
        // Animate number change
        const current = parseInt(el.textContent, 10) || 0;
        if (current !== value) {
          el.textContent = value;
          el.style.transition = 'transform 0.15s ease';
          el.style.transform = 'scale(1.15)';
          setTimeout(() => {
            el.style.transform = 'scale(1)';
          }, 150);
        }
      }
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SNAPSHOTS
     ═══════════════════════════════════════════════════════════════════════ */

  async fetchSnapshots() {
    try {
      const res = await fetch('/api/snapshots');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      this.renderSnapshots(data.snapshots || []);
    } catch (e) {
      console.error('[Sentinel] Failed to fetch snapshots:', e);
    }
  }

  /**
   * Render the snapshot list.
   * @param {Array<Object>} snapshots
   */
  renderSnapshots(snapshots) {
    const list = document.getElementById('snapshot-list');
    const empty = document.getElementById('snapshot-empty');

    if (snapshots.length === 0) {
      if (empty) empty.style.display = 'block';
      return;
    }

    if (empty) empty.style.display = 'none';

    // Remove existing items (preserve empty-state element)
    const existingItems = list.querySelectorAll('.snapshot-item');
    existingItems.forEach((el) => el.remove());

    document.getElementById('snapshot-count').textContent =
      `${snapshots.length} snapshot${snapshots.length !== 1 ? 's' : ''}`;

    for (const snap of snapshots) {
      const el = document.createElement('div');
      el.className = 'snapshot-item';
      el.setAttribute('data-name', snap.name);

      const time = new Date(snap.timestamp * 1000);
      const timeStr = time.toLocaleString();
      const sizeStr = this.formatBytes(snap.size_bytes || 0);
      const sevName = this.getSeverityName(snap.severity || 0);

      const safeId = snap.name.replace(/[^a-zA-Z0-9]/g, '_');

      el.innerHTML = `
        <div class="snapshot-name">📸 ${this.escapeHtml(snap.name)}</div>
        <div class="snapshot-meta">${timeStr} · ${sizeStr} · ${this.escapeHtml(sevName)}</div>
        <div class="snapshot-contents" id="snap-contents-${safeId}">
          <div class="spinner" style="margin: 10px auto;"></div>
        </div>
      `;

      el.addEventListener('click', (e) => {
        // Prevent toggle when clicking download link
        if (e.target.tagName === 'A') return;
        this.toggleSnapshot(el, snap.name);
      });

      list.appendChild(el);
    }
  }

  /**
   * Toggle snapshot expansion and lazy-load contents.
   * @param {HTMLElement} el - The snapshot-item element.
   * @param {string} name - Snapshot filename.
   */
  async toggleSnapshot(el, name) {
    const isExpanded = el.classList.contains('expanded');

    // Collapse all others
    document.querySelectorAll('.snapshot-item.expanded').forEach((item) => {
      item.classList.remove('expanded');
    });

    if (isExpanded) return;

    el.classList.add('expanded');

    // Fetch contents
    const contentsEl = el.querySelector('.snapshot-contents');
    try {
      const res = await fetch(
        `/api/snapshots/${encodeURIComponent(name)}/contents`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      contentsEl.innerHTML = this.renderSnapshotContents(data, name);
    } catch (e) {
      contentsEl.innerHTML =
        '<div class="text-muted" style="padding:8px;font-size:0.8rem;">Failed to load snapshot contents</div>';
    }
  }

  /**
   * Build HTML for expanded snapshot contents.
   * @param {Object} data - Snapshot contents JSON.
   * @param {string} name - Snapshot filename.
   * @returns {string} HTML string.
   */
  renderSnapshotContents(data, name) {
    let html = '';

    // ── Alert Metadata ────────────────────────────────────
    if (data.alert_metadata) {
      const meta = data.alert_metadata;
      html += `
        <div class="snapshot-section">
          <div class="snapshot-section-title">🔔 Alert Metadata</div>
          <div style="font-size:0.75rem;color:var(--text-secondary);padding:4px 0;font-family:'JetBrains Mono',monospace;">
            Source: ${this.escapeHtml(String(meta.source || 'N/A'))}<br>
            Severity: ${meta.severity != null ? meta.severity : 'N/A'}<br>
            Title: ${this.escapeHtml(String(meta.title || 'N/A'))}
          </div>
        </div>
      `;
    }

    // ── Processes ─────────────────────────────────────────
    if (data.processes && data.processes.length > 0) {
      const limit = 20;
      const procs = data.processes.slice(0, limit);
      html += `
        <div class="snapshot-section">
          <div class="snapshot-section-title">⚙️ Processes (${data.processes.length})</div>
          <table class="snapshot-table">
            <tr><th>PID</th><th>Name</th><th>PPID</th><th>User</th></tr>
            ${procs
              .map(
                (p) =>
                  `<tr><td>${p.pid || ''}</td><td>${this.escapeHtml(String(p.name || ''))}</td><td>${p.ppid || ''}</td><td>${this.escapeHtml(String(p.user || ''))}</td></tr>`
              )
              .join('')}
          </table>
          ${
            data.processes.length > limit
              ? `<div class="text-muted" style="font-size:0.7rem;margin-top:4px;">...and ${data.processes.length - limit} more</div>`
              : ''
          }
        </div>
      `;
    }

    // ── Network Connections ───────────────────────────────
    if (data.network && data.network.length > 0) {
      const limit = 15;
      const conns = data.network.slice(0, limit);
      html += `
        <div class="snapshot-section">
          <div class="snapshot-section-title">🌐 Network (${data.network.length})</div>
          <table class="snapshot-table">
            <tr><th>Local</th><th>Remote</th><th>Status</th><th>PID</th></tr>
            ${conns
              .map(
                (c) =>
                  `<tr><td>${this.escapeHtml(String(c.laddr || ''))}</td><td>${this.escapeHtml(String(c.raddr || ''))}</td><td>${c.status || ''}</td><td>${c.pid || ''}</td></tr>`
              )
              .join('')}
          </table>
          ${
            data.network.length > limit
              ? `<div class="text-muted" style="font-size:0.7rem;margin-top:4px;">...and ${data.network.length - limit} more</div>`
              : ''
          }
        </div>
      `;
    }

    // ── Registry Hives ────────────────────────────────────
    if (data.registry) {
      const keys = Object.keys(data.registry);
      if (keys.length > 0) {
        html += `
          <div class="snapshot-section">
            <div class="snapshot-section-title">📋 Registry (${keys.length} hives)</div>
            <div style="font-size:0.7rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;">
              ${keys.map((k) => `<div style="padding:2px 0;">▸ ${this.escapeHtml(k)}</div>`).join('')}
            </div>
          </div>
        `;
      }
    }

    // ── Temp Files ────────────────────────────────────────
    if (data.temp_files && data.temp_files.length > 0) {
      html += `
        <div class="snapshot-section">
          <div class="snapshot-section-title">📁 Temp Files (${data.temp_files.length})</div>
          <div style="font-size:0.7rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;max-height:100px;overflow-y:auto;">
            ${data.temp_files
              .slice(0, 10)
              .map((f) => `<div style="padding:1px 0;">${this.escapeHtml(String(f))}</div>`)
              .join('')}
            ${data.temp_files.length > 10 ? `<div class="text-muted" style="margin-top:2px;">...and ${data.temp_files.length - 10} more</div>` : ''}
          </div>
        </div>
      `;
    }

    // ── Prefetch ──────────────────────────────────────────
    if (data.prefetch && data.prefetch.length > 0) {
      html += `
        <div class="snapshot-section">
          <div class="snapshot-section-title">⏩ Prefetch (${data.prefetch.length})</div>
          <div style="font-size:0.7rem;color:var(--text-secondary);font-family:'JetBrains Mono',monospace;max-height:80px;overflow-y:auto;">
            ${data.prefetch
              .slice(0, 10)
              .map((p) => `<div style="padding:1px 0;">${this.escapeHtml(String(p))}</div>`)
              .join('')}
          </div>
        </div>
      `;
    }

    // ── Download Button ───────────────────────────────────
    html += `
      <div style="margin-top:8px;">
        <a href="/api/snapshots/${encodeURIComponent(name)}/download"
           class="btn btn-snapshot"
           style="display:inline-flex;padding:6px 12px;font-size:0.75rem;text-decoration:none;"
           download>
          ⬇ Download ZIP
        </a>
      </div>
    `;

    return html;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     CONTROLS
     ═══════════════════════════════════════════════════════════════════════ */

  async start() {
    const btn = document.getElementById('btn-start');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Starting...';

    try {
      const res = await fetch('/api/control/start', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast('Sentinel engine started', 'info');
      } else {
        this.showToast(
          'Failed to start: ' + (data.error || 'Unknown error'),
          'critical'
        );
        btn.disabled = false;
      }
    } catch (e) {
      this.showToast('Connection error — is the backend running?', 'critical');
      btn.disabled = false;
    }

    btn.innerHTML = '▶ Start';
  }

  async stop() {
    const btn = document.getElementById('btn-stop');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Stopping...';

    try {
      const res = await fetch('/api/control/stop', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast('Sentinel engine stopped', 'info');
      } else {
        this.showToast(
          'Failed to stop: ' + (data.error || 'Unknown error'),
          'critical'
        );
      }
    } catch (e) {
      this.showToast('Connection error', 'critical');
    }

    btn.innerHTML = '⏹ Stop';
  }

  async manualSnapshot() {
    const btn = document.getElementById('btn-snapshot');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Capturing...';

    try {
      const res = await fetch('/api/snapshots/manual', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast('Snapshot captured successfully', 'info');
        setTimeout(() => this.fetchSnapshots(), 1000);
      } else {
        this.showToast(
          'Snapshot failed: ' + (data.error || 'Unknown reason'),
          'critical'
        );
      }
    } catch (e) {
      this.showToast('Connection error', 'critical');
    }

    btn.disabled = false;
    btn.innerHTML = '📸 Snapshot';
  }

  clearAlerts() {
    this.alerts = [];
    this.stats = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      killed: 0,
      snapshots: 0,
    };
    this.chartData = [];

    const feed = document.getElementById('alert-feed-body');
    feed.innerHTML = `
      <div class="empty-state" id="alert-empty">
        <div class="empty-state-icon">🛡️</div>
        <div>No alerts — log cleared</div>
      </div>
    `;

    this.updateStats();
    this.drawChart();
    this.updateGauge();
    document.getElementById('alert-count').textContent = '0 alerts';
    this.showToast('Alert log cleared', 'info');
  }

  exportAlerts() {
    if (this.alerts.length === 0) {
      this.showToast('No alerts to export', 'info');
      return;
    }

    const blob = new Blob([JSON.stringify(this.alerts, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel_alerts_${new Date()
      .toISOString()
      .replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    this.showToast(`Exported ${this.alerts.length} alerts as JSON`, 'info');
  }

  async clearSnapshots() {
    const ok = confirm('Delete ALL forensic snapshots? This cannot be undone.');
    if (!ok) return;

    try {
      const res = await fetch('/api/snapshots/clear', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        this.showToast(`Cleared ${data.deleted} snapshot(s)`, 'info');
        this.fetchSnapshots();
      } else {
        this.showToast(
          'Failed to clear snapshots: ' + (data.error || 'Unknown error'),
          'critical'
        );
      }
    } catch (e) {
      this.showToast('Connection error', 'critical');
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     INITIAL DATA FETCH
     ═══════════════════════════════════════════════════════════════════════ */

  async fetchInitialData() {
    // ── Status ────────────────────────────────────────────
    try {
      const statusRes = await fetch('/api/status');
      if (statusRes.ok) {
        const status = await statusRes.json();
        this.updateStatus(status);
      }
    } catch (e) {
      console.error('[Sentinel] Failed to fetch initial status:', e);
    }

    // ── Recent Alerts ─────────────────────────────────────
    try {
      const alertsRes = await fetch('/api/alerts?limit=50');
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        if (alertsData.alerts && alertsData.alerts.length > 0) {
          // API returns newest-first; reverse to render oldest-first (append)
          const reversed = [...alertsData.alerts].reverse();
          for (const alert of reversed) {
            this.alerts.push(alert);
            this.chartData.push({
              timestamp: alert.timestamp * 1000,
              severity: alert.severity,
            });
            this.renderAlert(alert, false);

            // Update stats
            this.stats.total++;
            const sevName = this.getSeverityName(alert.severity).toLowerCase();
            if (this.stats[sevName] !== undefined) {
              this.stats[sevName]++;
            }
            if (alert.details && alert.details.process_killed) {
              this.stats.killed++;
            }
            if (alert.snapshot_requested) {
              this.stats.snapshots++;
            }
          }

          // Reverse in-memory so newest is first
          this.alerts.reverse();

          this.updateStats();
          this.drawChart();
          this.updateGauge();
        }
      }
    } catch (e) {
      console.error('[Sentinel] Failed to fetch initial alerts:', e);
    }

    // ── Snapshots ─────────────────────────────────────────
    this.fetchSnapshots();
  }

  /* ═══════════════════════════════════════════════════════════════════════
     TOAST NOTIFICATIONS
     ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Show a temporary toast notification.
   * @param {string} message - Text to display.
   * @param {string} severity - One of: info, low, medium, high, critical.
   */
  showToast(message, severity = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast severity-${severity}`;
    toast.textContent = message;
    container.appendChild(toast);

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
      toast.classList.add('fading');
      setTimeout(() => {
        if (toast.parentNode) {
          toast.remove();
        }
      }, 300);
    }, 4000);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     CLOCK
     ═══════════════════════════════════════════════════════════════════════ */

  startClock() {
    const update = () => {
      const el = document.getElementById('clock');
      if (el) {
        el.textContent = new Date().toLocaleTimeString('en-US', {
          hour12: false,
        });
      }
    };
    update();
    setInterval(update, 1000);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     HELPERS
     ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Map a numeric severity value to a name.
   * @param {number} value - Severity (0–100).
   * @returns {string}
   */
  getSeverityName(value) {
    if (value >= 100) return 'critical';
    if (value >= 75) return 'high';
    if (value >= 50) return 'medium';
    if (value >= 25) return 'low';
    return 'info';
  }

  /**
   * Map a numeric severity value to a hex color.
   * @param {number} value - Severity (0–100).
   * @returns {string}
   */
  getSeverityColor(value) {
    if (value >= 100) return '#ef4444';
    if (value >= 75) return '#f97316';
    if (value >= 50) return '#f59e0b';
    if (value >= 25) return '#10b981';
    return '#6b7280';
  }

  /**
   * Format bytes into a human-readable string.
   * @param {number} bytes
   * @returns {string}
   */
  formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  /**
   * Escape HTML entities to prevent XSS.
   * @param {string} text
   * @returns {string}
   */
  escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   BOOT
   ═══════════════════════════════════════════════════════════════════════════ */
const app = new SentinelApp();
