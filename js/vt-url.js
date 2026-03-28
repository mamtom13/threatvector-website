/* ================================================================
   vt-url.js — URL reputation check (full 4-step VT flow)

   Step 1: Check VirusTotal cache
   Step 2: Submit URL if not found
   Step 3: Poll analyses until completed
   Step 4: Render rich result + screenshot
================================================================ */
'use strict';

/* ── Cloudflare Worker proxy URL ────────────────────────────────
   Change ONLY this line if you redeploy the Worker.
─────────────────────────────────────────────────────────────────*/
const VT = 'https://vt-proxy.websentinel1990.workers.dev/vt';

/* ── Main entry point ────────────────────────────────────────── */
async function checkURL() {
  const raw = document.getElementById('urlInput').value.trim();
  const btn = document.getElementById('urlBtn');
  const box = document.getElementById('urlResult');
  if (!raw) { showToast('// Please enter a URL or domain', 'warn'); return; }

  // Normalize: add https:// if missing
  let clean = raw.replace(/\/$/, '');
  if (!/^https?:\/\//i.test(clean)) clean = 'https://' + clean;
  const urlId = urlToId(clean);

  btn.disabled = true;
  btn.textContent = '...';
  showLoading('urlResult', '// STEP 1/4 — Checking VirusTotal cache...');

  try {
    let reportData = null;

    /* Step 1 — Check cache */
    setStep('urlResult', '// STEP 1/4 — Checking VirusTotal cache...');
    const cached = await fetch(`${VT}/urls/${urlId}`);
    if (cached.ok) {
      const cj = await cached.json();
      if (cj.data?.attributes?.last_analysis_stats) reportData = cj.data;
    }

    /* Step 2 — Submit if not cached */
    if (!reportData) {
      setStep('urlResult', '// STEP 2/4 — Submitting URL to VirusTotal...');
      const submit = await fetch(`${VT}/urls`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    `url=${encodeURIComponent(clean)}`,
      });
      if (!submit.ok) throw new Error(`Submit failed — HTTP ${submit.status}`);
      const sj = await submit.json();
      const analysisId = sj.data?.id;
      if (!analysisId) throw new Error('No analysis ID returned from VirusTotal');

      /* Step 3 — Poll until complete */
      setStep('urlResult', '// STEP 3/4 — Waiting for analysis...');
      let tries = 0;
      while (tries < 20) {
        await sleep(3000);
        const poll = await fetch(`${VT}/analyses/${analysisId}`);
        if (poll.ok) {
          const pj    = await poll.json();
          const pStat = pj.data?.attributes?.status;
          const pMal  = pj.data?.attributes?.stats?.malicious ?? 0;
          setStep('urlResult', `// STEP 3/4 — Scanning... (${pMal} detections so far)`);
          if (pStat === 'completed') {
            const full = await fetch(`${VT}/urls/${urlId}`);
            if (full.ok) { reportData = (await full.json()).data; break; }
          }
        }
        tries++;
      }
      if (!reportData) throw new Error('Analysis timed out — wait a few seconds and try again.');
    }

    /* Step 4 — Render rich result */
    setStep('urlResult', '// STEP 4/4 — Rendering results...');
    renderVTResult(box, reportData, clean, urlId);
    fetchScreenshot(urlId); // async — non-blocking

  } catch (err) {
    box.innerHTML = renderResult({
      status: 'warn', label: 'ERROR',
      rows: [
        ['URL',   clean],
        ['ERROR', err.message, 'warn'],
        ['TIP',   'If this is a new URL, wait a few seconds and try again.'],
      ]
    });
  } finally {
    btn.disabled = false;
    btn.textContent = 'SCAN';
  }
}

/* ── Rich VT result layout ───────────────────────────────────── */
function renderVTResult(box, data, url, urlId) {
  const a       = data.attributes || {};
  const stats   = a.last_analysis_stats || {};
  const engines = a.last_analysis_results || {};

  const mal   = stats.malicious  || 0;
  const sus   = stats.suspicious || 0;
  const undet = stats.undetected || 0;
  const harm  = stats.harmless   || 0;
  const total = mal + sus + undet + harm;

  // Verdict
  let vCls, vIcon, vTitle, vColor;
  if      (mal >= 3)           { vCls='danger'; vIcon='🚨'; vColor='var(--red)';   vTitle=`Dangerous — flagged by ${mal} engines`; }
  else if (mal > 0 || sus > 0) { vCls='warn';   vIcon='⚠️'; vColor='var(--warn)';  vTitle=`Suspicious — ${mal+sus} engine(s) flagged`; }
  else                         { vCls='clean';  vIcon='✅'; vColor='var(--green)'; vTitle='No threats detected'; }

  // Engine rows — malicious & suspicious sorted first
  const allEng = Object.entries(engines);
  allEng.sort(([,a],[,b]) => {
    const s = r => r.category==='malicious'?3:r.category==='suspicious'?2:0;
    return s(b) - s(a);
  });
  const bad = allEng.filter(([,r]) => r.category==='malicious'||r.category==='suspicious');
  const engineHTML = bad.length
    ? bad.map(([name, r]) => {
        const lbl  = r.result || r.category;
        const disp = lbl.length > 28 ? lbl.slice(0, 28) + '…' : lbl;
        const cls  = r.category === 'malicious' ? 'eb-mal' : 'eb-sus';
        return `<div class="engine-row">
          <span class="engine-name">${name}</span>
          <span class="engine-badge ${cls}">${disp}</span>
        </div>`;
      }).join('')
    : `<div style="color:var(--green);font-family:var(--mono);font-size:11px;padding:4px 0">✓ No engines flagged this URL</div>`;

  const cats   = Object.values(a.categories || {}).join(', ') || 'N/A';
  const date   = a.last_analysis_date
    ? new Date(a.last_analysis_date * 1000).toLocaleString() : 'Just now';
  const vtLink = `https://www.virustotal.com/gui/url/${urlId}`;

  box.innerHTML = `
<div class="vt-result">

  <div class="vt-verdict ${vCls}">
    <div class="vt-verdict-icon">${vIcon}</div>
    <div class="vt-verdict-text">
      <h3 style="color:${vColor}">${vTitle}</h3>
      <p>${url} &nbsp;·&nbsp; Scanned: ${date}</p>
    </div>
    <div class="vt-score">
      <div class="sc-num" style="color:${vColor}">${mal}/${total}</div>
      <div class="sc-lbl">engines flagged</div>
    </div>
  </div>

  <div style="margin-bottom:12px">
    ${mRow('TITLE',      a.title || '—')}
    ${mRow('CATEGORIES', cats)}
    ${mRow('REPUTATION', a.reputation != null ? String(a.reputation) : 'N/A')}
    ${mRow('FINAL URL',  a.last_final_url || url)}
  </div>

  <div class="vt-cols">
    <div class="vt-box">
      <h4>🔍 Engine Results &nbsp;<span style="color:var(--red);font-weight:700">${bad.length} flagged</span></h4>
      <div class="engine-list">${engineHTML}</div>
    </div>
    <div class="vt-box">
      <h4>📸 Website Screenshot</h4>
      <div id="vtScreenWrap" style="min-height:80px;display:flex;align-items:center">
        <span style="color:var(--dim);font-family:var(--mono);font-size:10px">Loading…</span>
      </div>
    </div>
  </div>

  <div class="vt-footer">
    <a href="${vtLink}" target="_blank" rel="noopener" class="vt-link">🔗 View full report on VirusTotal →</a>
    <span class="vt-counts">
      🟢 ${harm} clean &nbsp;·&nbsp; 🔴 ${mal} malicious &nbsp;·&nbsp; 🟡 ${sus} suspicious &nbsp;·&nbsp; ⬜ ${undet} undetected
    </span>
  </div>

</div>`;
}

/* Helper — meta row */
function mRow(k, v) {
  return `<div class="r-row"><span class="r-key">${k}</span><span class="r-val">${v}</span></div>`;
}

/* Screenshot injected async into existing slot */
async function fetchScreenshot(urlId) {
  const wrap = document.getElementById('vtScreenWrap');
  if (!wrap) return;
  try {
    const res = await fetch(`${VT}/urls/${urlId}/screenshot`);
    if (!res.ok) throw new Error('not available');
    const blob   = await res.blob();
    const imgUrl = URL.createObjectURL(blob);
    wrap.innerHTML = `<img src="${imgUrl}" class="vt-screenshot" alt="Screenshot"
      onerror="this.parentElement.innerHTML='<span style=\\'color:var(--dim);font-family:var(--mono);font-size:10px\\'>Screenshot not available</span>'">`;
  } catch (_) {
    wrap.innerHTML = `<span style="color:var(--dim);font-family:var(--mono);font-size:10px">Screenshot not available</span>`;
  }
}
