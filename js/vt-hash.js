/* ================================================================
   vt-hash.js — File hash lookup via VirusTotal
   Supports: MD5 (32), SHA-1 (40), SHA-256 (64)
================================================================ */
'use strict';

async function checkHash() {
  const raw  = document.getElementById('hashInput').value.trim();
  const btn  = document.getElementById('hashBtn');
  const box  = document.getElementById('hashResult');
  if (!raw) { showToast('// Please enter a file hash', 'warn'); return; }

  // Validate hash format
  const hashType = raw.length === 32 ? 'MD5'
                 : raw.length === 40 ? 'SHA-1'
                 : raw.length === 64 ? 'SHA-256'
                 : null;
  if (!hashType) {
    showToast('// Invalid hash — MD5 (32 chars), SHA-1 (40), SHA-256 (64)', 'danger');
    return;
  }

  btn.disabled = true;
  btn.textContent = '...';
  showLoading('hashResult', '// Querying VirusTotal database...');

  try {
    const resp = await fetch(`${VT}/files/${raw}`);

    // Hash not in VT database
    if (resp.status === 404) {
      box.innerHTML = renderResult({
        status: 'neutral', label: 'NOT FOUND',
        rows: [
          ['HASH',   raw],
          ['TYPE',   hashType],
          ['STATUS', 'No analysis found. File may be unknown or never submitted to VirusTotal.', 'warn'],
        ]
      });
      return;
    }

    if (!resp.ok) throw new Error(`HTTP ${resp.status} — ${resp.statusText}`);

    const jd    = await resp.json();
    const a     = jd.data?.attributes || {};
    const stats = a.last_analysis_stats || {};
    const total = Object.values(stats).reduce((x, y) => x + y, 0);
    const mal   = stats.malicious || 0;

    // Verdict
    let status = 'safe', label = 'CLEAN';
    if      (mal > 5) { status = 'danger'; label = 'MALWARE DETECTED';      }
    else if (mal > 0) { status = 'warn';   label = 'POTENTIALLY MALICIOUS'; }

    const names  = (a.names || []).slice(0, 3).join(', ') || 'N/A';
    const family = a.popular_threat_classification?.suggested_threat_label || 'N/A';
    const pct    = total > 0 ? Math.round((mal / total) * 100) : 0;

    box.innerHTML = renderResult({ status, label, rows: [
      ['HASH',         raw],
      ['HASH TYPE',    hashType],
      ['FILE NAMES',   names],
      ['FILE TYPE',    a.type_description || 'N/A'],
      ['FILE SIZE',    a.size ? `${(a.size / 1024).toFixed(1)} KB` : 'N/A'],
      ['DETECTIONS',   `${mal} / ${total} vendors`,
                       mal > 5 ? 'danger' : mal > 0 ? 'warn' : 'safe'],
      ['THREAT LABEL', family, family !== 'N/A' ? 'danger' : ''],
      ['FIRST SEEN',   a.first_submission_date
                         ? new Date(a.first_submission_date * 1000).toUTCString() : 'N/A'],
      ['LAST SEEN',    a.last_analysis_date
                         ? new Date(a.last_analysis_date * 1000).toUTCString() : 'N/A'],
      ['VT REPORT',    `https://www.virustotal.com/gui/file/${raw}`],
    ]}) +
    `<div class="vt-gauge">
       <div class="vt-gauge-fill ${status}" style="width:${pct}%"></div>
     </div>`;

  } catch (err) {
    box.innerHTML = renderResult({
      status: 'warn', label: 'ERROR',
      rows: [
        ['HASH',  raw],
        ['TYPE',  hashType],
        ['ERROR', err.message, 'warn'],
      ]
    });
  } finally {
    btn.disabled = false;
    btn.textContent = 'LOOKUP';
  }
}
