/**
 * CYBERWATCH DASHBOARD — app.js
 *
 * Loading strategy:
 *  1. fetch('data/intel.json') — GitHub Pages / local server
 *  2. window.INTEL_DATA fallback — file:// protocol
 *
 * AI Features:
 *  - Cards expand on click → AI analysis panel (summary + severity + graph)
 *  - Mermaid attack-flow diagram lazily rendered via mermaid.render()
 */

// ─── Mermaid Config (dark terminal theme) ─────────────────────────────────────
if (typeof mermaid !== 'undefined') {
  mermaid.initialize({
    startOnLoad:   false,
    theme:         'dark',
    securityLevel: 'loose',
    themeVariables: {
      background:          '#080b0f',
      mainBkg:             '#0d1117',
      primaryColor:        '#0d2038',
      primaryTextColor:    '#c9d8e8',
      primaryBorderColor:  '#1e4d73',
      lineColor:           '#4da6ff',
      secondaryColor:      '#111820',
      tertiaryColor:       '#080b0f',
      edgeLabelBackground: '#080b0f',
      fontFamily:          "'JetBrains Mono', 'Courier New', monospace",
      fontSize:            '12px',
      nodeBorder:          '#1e2d3d',
      clusterBkg:          '#0d1117',
    },
    flowchart: { htmlLabels: false, curve: 'Linear', padding: 24 },
  });
}

// ─── State ────────────────────────────────────────────────────────────────────
let allItems     = [];
let filteredItems = [];
let activeFilter  = 'all';
let activeSeverity = null;
let searchQuery   = '';
let mermaidSeq    = 0;   // unique ID counter for each mermaid diagram

// ─── Entry Point ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  initSearch();
  initSeverityFilters();
  loadIntelData();
});

// ─── Load Data ────────────────────────────────────────────────────────────────
async function loadIntelData() {
  try {
    let data;

    if (window.location.protocol !== 'file:') {
      const response = await fetch(`data/intel.json?v=${Date.now()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } else {
      if (window.INTEL_DATA) {
        data = window.INTEL_DATA;
        const meta = document.getElementById('last-updated');
        if (meta) {
          meta.textContent = '⚠ Preview mode (open via server for live data)';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data — open via a server or GitHub Pages');
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc  = date.toUTCString();
      const ist  = date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'medium'
      });
      document.getElementById('last-updated').textContent =
        `Last updated: ${utc} | IST: ${ist}`;
    }

    renderSidebar();
    renderDailySummary();
    applyFilters();
    showContent();

  } catch (err) {
    console.error('Failed to load intel.json:', err);
    showError();
  }
}

// ─── Filter & Search Logic ────────────────────────────────────────────────────
function applyFilters() {
  if (activeFilter === 'matrix') {
    showMatrixView();
    return;
  }
  

  filteredItems = allItems.filter(item => {
    const catMatch = activeFilter === 'all' || item.category === activeFilter;
    if (!catMatch) return false;

    if (activeSeverity && (item.severity||'').toLowerCase() !== activeSeverity) {
      return false;
    }

    const q = searchQuery.toLowerCase();
    if (!q) return true;
    return (
      (item.title       && item.title.toLowerCase().includes(q))       ||
      (item.description && item.description.toLowerCase().includes(q)) ||
      (item.cve_id      && item.cve_id.toLowerCase().includes(q))      ||
      (item.source      && item.source.toLowerCase().includes(q))      ||
      (item.ai_summary  && item.ai_summary.toLowerCase().includes(q))  ||
      (item.ttps && item.ttps.some(t =>
        t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      ))
    );
  });

  showContent();
  renderCards();
  updateHeaderStats();
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
function initFilters() {
  document.getElementById('filter-tabs').addEventListener('click', e => {
    const btn = e.target.closest('.filter-btn');
    if (!btn) return;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    applyFilters();
  });
}

function initSearch() {
  const input = document.getElementById('search-input');
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      searchQuery = input.value.trim();
      applyFilters();
    }, 250);
  });
}

function initSeverityFilters() {
  document.querySelectorAll('.stat-pill').forEach(pill => {
    pill.style.cursor = 'pointer';
    pill.addEventListener('click', () => {
      const sev = pill.id.replace('stat-', '');
      if (sev === 'items') {
        activeSeverity = null;
        document.querySelectorAll('.stat-pill').forEach(p => p.classList.remove('active'));
      } else {
        if (activeSeverity === sev) {
          activeSeverity = null;
          pill.classList.remove('active');
        } else {
          activeSeverity = sev;
          document.querySelectorAll('.stat-pill').forEach(p => p.classList.remove('active'));
          pill.classList.add('active');
        }
      }
      applyFilters();
    });
  });
}

// ─── Render Cards ─────────────────────────────────────────────────────────────
function renderCards() {
  const container = document.getElementById('cards-container');
  const noResults = document.getElementById('no-results');
  const feedCount = document.getElementById('feed-count');

  container.innerHTML = '';

  if (filteredItems.length === 0) {
    noResults.style.display = 'block';
    feedCount.textContent   = 'No items found';
    return;
  }

  noResults.style.display = 'none';
  feedCount.textContent = `${filteredItems.length} item${filteredItems.length !== 1 ? 's' : ''} in feed`;

  const sorted = [...filteredItems].sort(
    (a, b) => new Date(b.published || 0) - new Date(a.published || 0)
  );

  sorted.forEach((item, index) => container.appendChild(buildCard(item, index)));
}

// ─── Build Card ───────────────────────────────────────────────────────────────
function buildCard(item, index) {
  const card  = document.createElement('div');
  const mySeq = ++mermaidSeq;

  const isNew = item.published &&
    (Date.now() - new Date(item.published)) < 86_400_000;

  card.className = 'intel-card';
  if (isNew) card.classList.add('new-item');

  // ── FIX: was item.aisummary (wrong) → now item.ai_summary (correct) ────────
  const hasAI = item.ai_summary &&
                item.ai_summary !== 'AI analysis pending' &&
                item.ai_summary !== '';

  if (hasAI) card.classList.add('ai-enriched');

  card.dataset.category = item.category || 'news';
  card.style.animationDelay = `${index * 0.04}s`;

  const severity       = (item.severity || 'medium').toLowerCase();
  const providerLabel  = (item.ai_provider || 'AI').toUpperCase();
  const modelLabel     = item.ai_model || item.ai_provider || 'AI';

  const badgeHTML    = `<span class="badge ${severity}">${severity.toUpperCase()}</span>`;
  const newBadgeHTML = isNew ? `<span class="new-item-badge">NEW</span>` : '';
  const aiBadgeHTML  = hasAI
    ? `<span class="ai-badge" title="Enriched by ${escapeHTML(providerLabel)}: ${escapeHTML(modelLabel)}">${escapeHTML(providerLabel)}</span>`
    : '';

  // Threat actor badges
  const threatActorHTML = (item.threat_actors && item.threat_actors.length > 0)
    ? item.threat_actors.slice(0, 2).map(actor => 
        `<span class="threat-actor-badge" onclick="event.stopPropagation();filterByThreatActor('${escapeHTML(actor)}')" title="Filter by ${escapeHTML(actor)}">${escapeHTML(actor)}</span>`
      ).join('')
    : '';

  // CISA KEV badge
  const cisaKevHTML = item.cisa_kev
    ? `<span class="cisa-kev-badge" title="Known Exploited Vulnerability (CISA KEV)">KEV</span>`
    : '';

  const cveIdHTML  = item.cve_id ? `<span class="cve-id" onclick="event.stopPropagation();openCveModal('${escapeHTML(item.cve_id)}')" title="Click for CVE details">${escapeHTML(item.cve_id)}</span> · ` : '';
  const descHTML   = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>` : '';
  const dateStr    = item.published ? timeAgo(new Date(item.published)) : '';
  const cvssHTML   = item.cvss_score
    ? `<span class="meta-tag meta-cvss">CVSS ${item.cvss_score.toFixed(1)}</span>` : '';
  const aiScoreHTML = (item.severity_score != null)
    ? `<span class="meta-tag meta-ai-score" title="AI severity score: ${escapeHTML(modelLabel)}">✦ AI ${item.severity_score.toFixed(1)}</span>`
    : '';

  const epssHTML = (item.epss_score != null)
    ? `<span class="meta-tag meta-epss" title="EPSS: ${(item.epss_score * 100).toFixed(2)}% probability of exploit in 30 days">✦ EPSS ${(item.epss_score * 100).toFixed(1)}%</span>`
    : '';

  // Analysis section — graph source is unescaped for Mermaid
  const graphSource    = (item.workflow_graph || '').replace(/\\n/g, '\n');
  const aiSummaryText  = item.ai_summary || '';

  const analysisHTML = `
    <div class="analysis-section" id="analysis-${mySeq}">
      <div class="analysis-header">
        <span class="analysis-label">AI THREAT ANALYSIS</span>
        <span class="analysis-model">${escapeHTML(modelLabel)}</span>
      </div>
      <p class="analysis-summary">${escapeHTML(aiSummaryText)}</p>
      ${graphSource ? `
      <div class="analysis-graph-wrap">
        <div class="analysis-graph-label">ATTACK FLOW</div>
        <div class="mermaid-container" id="mermaid-${mySeq}" data-graph="${escapeHTML(graphSource)}" data-rendered="false">
          <div class="mermaid-spinner">
            <div class="mermaid-spinner-ring"></div>
            <span>Rendering diagram…</span>
          </div>
        </div>
      </div>` : ''}
    </div>
  `;

  const expandHintHTML = `
    <div class="card-expand-hint">
      ${hasAI ? '▼ EXPAND AI ANALYSIS' : '▼ EXPAND'}
    </div>`;

  card.innerHTML = `
    <div class="card-top">
      <p class="card-title">
        ${item.url
          ? `<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener"
               onclick="event.stopPropagation()">${escapeHTML(item.title)}</a>`
          : escapeHTML(item.title)
        }
        ${newBadgeHTML}${aiBadgeHTML}${cisaKevHTML}
      </p>
      ${badgeHTML}
    </div>
    ${threatActorHTML ? `<div class="card-actors">${threatActorHTML}</div>` : ''}
    ${descHTML}
    <div class="card-meta">
      ${cveIdHTML}
      <span class="meta-tag meta-source">${escapeHTML(item.source || 'unknown')}</span>
      <span class="meta-tag meta-cat">${escapeHTML(item.category || 'general')}</span>
      ${cvssHTML}${aiScoreHTML}${epssHTML}
      <span class="meta-date">${dateStr}</span>
    </div>
    ${analysisHTML}
    ${expandHintHTML}
  `;

  // ── Card click → toggle expand + lazy-render Mermaid ────────────────────────
  card.addEventListener('click', e => {
    if (e.target.closest('a')) return;

    const wasExpanded = card.classList.contains('expanded');
    card.classList.toggle('expanded');

    if (!wasExpanded && graphSource) {
      const container = card.querySelector(`#mermaid-${mySeq}`);
      if (container && container.dataset.rendered === 'false') {
        container.dataset.rendered = 'true';
        renderMermaidAsync(container, graphSource, mySeq, item);
      }
    }
  });

  return card;
}

// ─── Mermaid Async Renderer ───────────────────────────────────────────────────
async function renderMermaidAsync(container, graphSource, seqId, item) {
  if (typeof mermaid === 'undefined') {
    container.innerHTML = '<p class="mermaid-error">Mermaid.js not loaded</p>';
    return;
  }
  try {
    const diagramId = `mermaid-diagram-${seqId}`;
    const { svg }   = await mermaid.render(diagramId, graphSource);

    container.innerHTML = svg;

    const svgEl = container.querySelector('svg');
    if (svgEl) {
      svgEl.style.maxWidth  = '100%';
      svgEl.style.height    = 'auto';
      svgEl.style.display   = 'block';
      svgEl.removeAttribute('width');
      svgEl.removeAttribute('height');
    }

  } catch (err) {
    console.warn('Mermaid render error:', err);
    // Show cleaned graph source as readable fallback
    const pre  = document.createElement('pre');
    pre.className   = 'mermaid-raw-fallback';
    pre.textContent = graphSource;
    container.innerHTML = '';
    container.appendChild(pre);
  }
}

// Jump to a card in the feed by title fragment
window.jumpToItem = function(titleFrag) {
  activeFilter = 'all';
  searchQuery  = titleFrag;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = titleFrag;
  showContent();
  applyFilters();
  // Briefly highlight the first result
  setTimeout(() => {
    const first = document.querySelector('.intel-card');
    if (first) {
      first.scrollIntoView({ behavior: 'smooth', block: 'center' });
      first.style.outline = '2px solid var(--accent-cyan)';
      setTimeout(() => { if (first) first.style.outline = ''; }, 2500);
    }
  }, 150);
};

// ─── Render Sidebar ───────────────────────────────────────────────────────────
function renderSidebar() {
  renderSeverityBars();
  renderSourceList();
  renderCategoryList();
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allItems.forEach(i => {
    const s = (i.severity || '').toLowerCase();
    if (s in counts) counts[s]++;
  });
  const max = Math.max(...Object.values(counts), 1);
  Object.entries(counts).forEach(([sev, count]) => {
    document.getElementById(`bar-${sev}`).style.width = `${(count / max) * 100}%`;
    document.getElementById(`sev-count-${sev}`).textContent = count;
  });
}

function renderSourceList() {
  const counts = {};
  allItems.forEach(i => { const s = i.source || 'unknown'; counts[s] = (counts[s] || 0) + 1; });
  document.getElementById('source-list').innerHTML =
    Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, count]) => `
      <div class="source-item">
        <span class="source-name">${escapeHTML(name)}</span>
        <span class="source-badge">${count}</span>
      </div>`).join('');
}

function renderCategoryList() {
  const counts = {};
  allItems.forEach(i => { const c = i.category || 'general'; counts[c] = (counts[c] || 0) + 1; });
  document.getElementById('cat-list').innerHTML =
    Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([cat, count]) => `
      <div class="cat-item" onclick="filterByCategory('${cat}')">
        <span class="cat-name">${escapeHTML(cat)}</span>
        <span class="cat-count">${count}</span>
      </div>`).join('');
}

window.filterByCategory = function(cat) {
  activeFilter = cat;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === cat)
  );
  applyFilters();
};

window.filterByThreatActor = function(actor) {
  activeFilter = 'all';
  searchQuery = actor;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = actor;
  showContent();
  applyFilters();
};

// ─── Header Stats ─────────────────────────────────────────────────────────────
function updateHeaderStats() {
  const critical = filteredItems.filter(i => (i.severity||'').toLowerCase() === 'critical').length;
  const high     = filteredItems.filter(i => (i.severity||'').toLowerCase() === 'high').length;
  const medium   = filteredItems.filter(i => (i.severity||'').toLowerCase() === 'medium').length;
  document.getElementById('count-critical').textContent = critical;
  document.getElementById('count-high').textContent     = high;
  document.getElementById('count-medium').textContent   = medium;
  document.getElementById('count-total').textContent    = filteredItems.length;
}

// ─── UI State Transitions ─────────────────────────────────────────────────────
function showContent() {
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('matrix-view').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'flex';
}

function showError() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'block';
}

function showMatrixView() {
  if (allItems.length === 0) {
    document.getElementById('loading-state').style.display = 'flex';
    return;
  }
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'none';
  document.getElementById('no-results').style.display      = 'none';
  document.getElementById('matrix-view').style.display     = 'block';
  renderMatrixGrid();
  document.getElementById('feed-count').textContent =
    'MITRE ATT&CK Coverage Map — click any technique to filter feed';
}

// ─── Daily Summary Bar ────────────────────────────────────────────────────────
function renderDailySummary() {
  const bar   = document.getElementById('daily-summary');
  const stats = document.getElementById('summary-stats');
  const top   = document.getElementById('summary-top-threat');
  if (!bar || !stats) return;

  const critical   = allItems.filter(i => i.severity === 'critical').length;
  const high       = allItems.filter(i => i.severity === 'high').length;
  const medium     = allItems.filter(i => i.severity === 'medium').length;
  const newItems   = allItems.filter(i => i.published && Date.now()-new Date(i.published)<86400000).length;
  const incidents  = allItems.filter(i => i.category === 'incident').length;
  const cves       = allItems.filter(i => i.category === 'cve').length;
  const advisories = allItems.filter(i => i.category === 'advisory').length;
  // ── FIX: was item.aisummary (wrong) → now item.ai_summary (correct) ────────
  const aiEnriched = allItems.filter(i =>
    i.ai_summary && i.ai_summary !== 'AI analysis pending' && i.ai_summary !== ''
  ).length;

  stats.innerHTML = `
    <span class="summary-stat"><span class="summary-stat-val c">${critical}</span><span class="summary-stat-lbl">CRITICAL</span></span>
    <span class="summary-stat"><span class="summary-stat-val h">${high}</span><span class="summary-stat-lbl">HIGH</span></span>
    <span class="summary-stat"><span class="summary-stat-val m">${medium}</span><span class="summary-stat-lbl">MEDIUM</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val n">${cves}</span><span class="summary-stat-lbl">CVEs</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${incidents}</span><span class="summary-stat-lbl">INCIDENTS</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${advisories}</span><span class="summary-stat-lbl">ADVISORIES</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val" style="color:var(--accent-cyan)">${newItems}</span><span class="summary-stat-lbl">NEW TODAY</span></span>
    <span class="summary-stat"><span class="summary-stat-val" style="color:#a78bfa">${aiEnriched}</span><span class="summary-stat-lbl">AI ENRICHED</span></span>
  `;

  const topThreat = allItems.find(i => i.severity === 'critical') ||
                    allItems.find(i => i.severity === 'high');
  if (top && topThreat) {
    top.innerHTML = `🔴 Top threat: <strong>${escapeHTML(topThreat.title.substring(0,80))}${topThreat.title.length>80?'…':''}</strong>`;
    top.style.cursor = 'pointer';
    top.onclick = () => {
      activeFilter = 'all';
      searchQuery = '';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
      applyFilters();
      setTimeout(() => {
        const firstCard = document.querySelector('.intel-card');
        if (firstCard) {
          firstCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
          firstCard.classList.add('expanded');
        }
      }, 100);
    };
  }
  bar.style.display = 'block';
}

// ─── Mobile Sidebar Toggle ────────────────────────────────────────────────────
window.toggleMobileSidebar = function() {
  const sidebar = document.querySelector('.sidebar');
  const label   = document.getElementById('toggle-label');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('mobile-open');
  if (label) label.textContent = isOpen ? '▲ HIDE STATS' : '▼ SHOW STATS';
};

// ─── CVE Deep-Dive Modal ─────────────────────────────────────────────────────
window.openCveModal = function(cveId) {
  const modal = document.getElementById('cve-modal');
  const modalTitle = document.getElementById('modal-cve-id');
  const modalBody = document.getElementById('modal-body');
  
  if (!modal || !modalTitle || !modalBody) return;
  
  modalTitle.textContent = cveId;
  modalBody.innerHTML = `
    <div class="modal-loading">
      <div class="loader-ring"></div>
      <span>Fetching NVD details...</span>
    </div>
  `;
  modal.style.display = 'flex';
  
  fetchCveDetails(cveId);
};

window.closeCveModal = function() {
  const modal = document.getElementById('cve-modal');
  if (modal) modal.style.display = 'none';
};

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeCveModal();
});

document.getElementById('cve-modal')?.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) closeCveModal();
});

async function fetchCveDetails(cveId) {
  const modalBody = document.getElementById('modal-body');
  if (!modalBody) return;
  
  // Validate CVE ID format
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
    modalBody.innerHTML = '<div class="modal-error">Invalid CVE ID format</div>';
    return;
  }
  
  // Rate limiting: retry with exponential backoff
  const maxRetries = 3;
  let lastError = null;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const resp = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`);
      
      if (resp.status === 429) {
        // Rate limited - wait and retry
        const waitTime = Math.pow(2, attempt) * 1000;
        console.warn(`Rate limited, retrying in ${waitTime}ms...`);
        await new Promise(r => setTimeout(r, waitTime));
        continue;
      }
      
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      
      const vuln = data?.vulnerabilities?.[0]?.cve;
      if (!vuln) throw new Error('CVE not found');
      
      const descriptions = vuln.descriptions || [];
      const description = descriptions.find(d => d.lang === 'en')?.value || 'No description available.';
      
      let cvssScore = null, cvssVector = null, severity = 'UNKNOWN';
      for (const metric of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
        const m = vuln.metrics?.[metric];
        if (m?.length) {
          cvssScore = m[0].cvssData?.baseScore;
          cvssVector = m[0].cvssData?.vectorString;
          severity = m[0].cvssData?.baseSeverity || severity;
          break;
        }
      }
      
      const references = (vuln.references || []).slice(0, 8).map(ref => 
        `<a class="modal-ref-link" href="${escapeHTML(ref.url)}" target="_blank" rel="noopener">${escapeHTML(ref.url)}</a>`
      ).join('');
      
      const published = vuln.published ? new Date(vuln.published).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'N/A';
      const lastModified = vuln.lastModified ? new Date(vuln.lastModified).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'N/A';
      
      const item = allItems.find(i => i.cve_id?.toUpperCase() === cveId.toUpperCase());
      const epssScore = item?.epss_score != null ? item.epss_score : null;
      const epssPercentile = epssScore != null ? (epssScore * 100).toFixed(2) : 'N/A';
      
      const severityClass = severity.toLowerCase();
      
      modalBody.innerHTML = `
        <div class="modal-section">
          <div class="modal-section-title">Overview</div>
          <div class="modal-grid">
            <div class="modal-stat">
              <div class="modal-stat-label">Published</div>
              <div class="modal-stat-value">${published}</div>
            </div>
            <div class="modal-stat">
              <div class="modal-stat-label">Last Modified</div>
              <div class="modal-stat-value">${lastModified}</div>
            </div>
            <div class="modal-stat">
              <div class="modal-stat-label">CVSS Score</div>
              <div class="modal-stat-value ${severityClass}">${cvssScore ?? 'N/A'}</div>
            </div>
            <div class="modal-stat">
              <div class="modal-stat-label">Severity</div>
              <div class="modal-stat-value ${severityClass}">${escapeHTML(severity)}</div>
            </div>
            ${epssScore != null ? `
            <div class="modal-stat">
              <div class="modal-stat-label">EPSS Score</div>
              <div class="modal-stat-value">${epssScore.toFixed(4)}</div>
            </div>
            <div class="modal-stat">
              <div class="modal-stat-label">EPSS Percentile</div>
              <div class="modal-stat-value">${epssPercentile}%</div>
            </div>
            ` : ''}
          </div>
          ${epssScore != null ? `
          <div class="modal-section" style="margin-top:12px;">
            <div class="modal-section-title">Exploit Prediction (EPSS)</div>
            <div class="modal-epss-bar">
              <div class="modal-epss-fill" style="width:${epssPercentile}%"></div>
            </div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Percentile: ${epssPercentile}% — This CVE is predicted to have exploit activity within the next 30 days.</div>
          </div>
          ` : ''}
        </div>
        
        <div class="modal-section">
          <div class="modal-section-title">Description</div>
          <div class="modal-description">${escapeHTML(description)}</div>
        </div>
        
        ${cvssVector ? `
        <div class="modal-section">
          <div class="modal-section-title">CVSS Vector</div>
          <div class="modal-description" style="font-family:var(--font-mono);font-size:11px;word-break:break-all;">${escapeHTML(cvssVector)}</div>
        </div>
        ` : ''}
        
        ${references ? `
        <div class="modal-section">
          <div class="modal-section-title">References</div>
          <div class="modal-refs">${references}</div>
        </div>
        ` : ''}
      `;
      
      return; // Success - exit the retry loop
      
    } catch (err) {
      lastError = err;
      console.error('CVE fetch error:', err);
      
      // If it's a 429, the outer loop will handle retry
      // Otherwise, don't retry on other errors
      if (err.message !== 'HTTP 429') {
        break;
      }
    }
  }
  
  // All retries failed
  modalBody.innerHTML = `<div class="modal-error">Failed to load CVE details: ${escapeHTML(lastError?.message || 'Unknown error')}</div>`;
}

// ─── MITRE ATT&CK Matrix ─────────────────────────────────────────────────────
const TACTIC_ORDER = [
  { id: "TA0043", name: "Reconnaissance"    },
  { id: "TA0042", name: "Resource Dev"      },
  { id: "TA0001", name: "Initial Access"    },
  { id: "TA0002", name: "Execution"         },
  { id: "TA0003", name: "Persistence"       },
  { id: "TA0004", name: "Privilege Esc"     },
  { id: "TA0005", name: "Defense Evasion"   },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery"         },
  { id: "TA0008", name: "Lateral Movement"  },
  { id: "TA0009", name: "Collection"        },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration"      },
  { id: "TA0040", name: "Impact"            },
];

function renderMatrixGrid() {
  const grid = document.getElementById('matrix-grid');
  if (!grid) return;

  const tacticMap = {};
  TACTIC_ORDER.forEach(t => { tacticMap[t.id] = {}; });

  allItems.forEach(item => {
    (item.ttps || []).forEach(ttp => {
      if (!tacticMap[ttp.tactic_id]) tacticMap[ttp.tactic_id] = {};
      if (!tacticMap[ttp.tactic_id][ttp.id]) {
        tacticMap[ttp.tactic_id][ttp.id] = { name: ttp.name, count: 0, items: [] };
      }
      tacticMap[ttp.tactic_id][ttp.id].count++;
      tacticMap[ttp.tactic_id][ttp.id].items.push(item.title);
    });
  });

  grid.innerHTML = TACTIC_ORDER.map(tactic => {
    const techniques  = tacticMap[tactic.id] || {};
    const techEntries = Object.entries(techniques).sort((a, b) => b[1].count - a[1].count);
    const totalCount  = techEntries.reduce((s, [, d]) => s + d.count, 0);
    const cells = techEntries.map(([techId, data]) => {
      const intensity = data.count >= 3 ? 'high' : 'med';
      const tooltip   = `${data.count} item(s): ${data.items.slice(0,2).join(' | ')}${data.items.length>2?'...':''}`;
      return `
        <div class="tech-cell active-${intensity}"
             title="${escapeHTML(tooltip)}"
             onclick="filterByTechnique('${techId}')">
          <span class="tech-id">${escapeHTML(techId)}</span>
          <span class="tech-name">${escapeHTML(data.name)}</span>
          <span class="tech-count">${data.count}</span>
        </div>`;
    }).join('');
    return `
      <div class="tactic-col">
        <div class="tactic-header">
          <span class="tactic-name">${escapeHTML(tactic.name)}</span>
          <span class="tactic-count">${techEntries.length > 0 ? totalCount : '—'}</span>
        </div>
        <div class="tactic-cells">
          ${cells || `<div class="tech-cell inactive"><span class="tech-name">No hits</span></div>`}
        </div>
      </div>`;
  }).join('');
}

window.filterByTechnique = function(techId) {
  activeFilter = 'all';
  searchQuery  = techId;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = techId;
  showContent();
  applyFilters();
};

// ─── Utilities ────────────────────────────────────────────────────────────────
function timeAgo(date) {
  const diff  = Date.now() - date;
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (isNaN(diff)) return '';
  if (mins  <  1)  return 'just now';
  if (mins  < 60)  return `${mins}m ago`;
  if (hours < 24)  return `${hours}h ago`;
  if (days  <  7)  return `${days}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ─── Keyboard Shortcuts ─────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
  
  switch(e.key) {
    case '/':
      e.preventDefault();
      document.getElementById('search-input')?.focus();
      break;
    case 'Escape':
      closeCveModal();
      const matrixView = document.getElementById('matrix-view');
      if (matrixView?.style.display === 'block') {
        showContent();
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
        activeFilter = 'all';
        applyFilters();
      }
      break;
    case 'c':
      activeFilter = 'cve';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'cve'));
      showContent();
      applyFilters();
      break;
    case 'n':
      activeFilter = 'news';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'news'));
      showContent();
      applyFilters();
      break;
    case 'a':
      activeFilter = 'advisory';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'advisory'));
      showContent();
      applyFilters();
      break;
    case 'i':
      activeFilter = 'incident';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'incident'));
      showContent();
      applyFilters();
      break;
    case 'm':
      activeFilter = 'matrix';
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === 'matrix'));
      applyFilters();
      break;
    
  }
});

// ─── Error Boundary ──────────────────────────────────────────────────────
window.onerror = function(msg, url, line, col, error) {
  console.error('Global error:', msg, 'at', url, ':', line);
  const errorDiv = document.getElementById('error-state');
  if (errorDiv) {
    errorDiv.innerHTML = `
      <p class="error-icon">⚠</p>
      <p>An unexpected error occurred.</p>
      <p class="error-detail">${escapeHTML(msg)}</p>
      <button onclick="location.reload()" class="retry-btn">Retry</button>
    `;
    errorDiv.style.display = 'block';
  }
  document.getElementById('loading-state').style.display = 'none';
  return true;
};

window.onunhandledrejection = function(event) {
  console.error('Unhandled rejection:', event.reason);
};

// ─── Resizable Sidebar ───────────────────────────────────────────────────
function initResizableSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const dashboard = document.querySelector('.dashboard');
  if (!sidebar || !dashboard) return;
  
  const handle = document.createElement('div');
  handle.className = 'resize-handle';
  sidebar.appendChild(handle);
  
  let isResizing = false;
  let startX = 0;
  let startWidth = 0;
  
  handle.addEventListener('mousedown', (e) => {
    isResizing = true;
    startX = e.clientX;
    startWidth = sidebar.offsetWidth;
    handle.classList.add('active');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });
  
  document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;
    const diff = e.clientX - startX;
    const newWidth = Math.max(200, Math.min(500, startWidth + diff));
    sidebar.style.width = newWidth + 'px';
    sidebar.style.flex = 'none';
  });
  
  document.addEventListener('mouseup', () => {
    if (isResizing) {
      isResizing = false;
      handle.classList.remove('active');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      localStorage.setItem('sidebarWidth', sidebar.offsetWidth);
    }
  });
  
  // Restore saved width
  const savedWidth = localStorage.getItem('sidebarWidth');
  if (savedWidth) {
    sidebar.style.width = savedWidth + 'px';
    sidebar.style.flex = 'none';
  }
}

// Initialize resizable sidebar when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  initResizableSidebar();
});

// ─── Service Worker Registration (Offline Mode) ─────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then(
      (registration) => {
        console.log('SW registered:', registration.scope);
      },
      (err) => {
        console.log('SW registration failed:', err);
      }
    );
  });
}