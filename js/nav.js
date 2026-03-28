/* ================================================================
   nav.js — Navigation, counters, flash, toast, shared utilities
================================================================ */
'use strict';

/* ── Navigation ─────────────────────────────────────────────── */
function nav(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(pageId);
  if (target) target.classList.add('active');
  document.querySelectorAll('.nav-menu a').forEach(a =>
    a.classList.toggle('active', a.dataset.p === pageId)
  );
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (pageId === 'home') initCounters();
}

/* ── Counter animation ──────────────────────────────────────── */
let countersRan = false;
function initCounters() {
  if (countersRan) return;
  countersRan = true;
  [
    { id: 's1', val: 14820, sfx: ''  },
    { id: 's2', val: 3241,  sfx: ''  },
    { id: 's3', val: 8906,  sfx: ''  },
    { id: 's4', val: 5,     sfx: '+' },
  ].forEach(({ id, val, sfx }) => {
    const el = document.getElementById(id);
    if (!el) return;
    let cur = 0;
    const step = Math.max(1, Math.ceil(val / 55));
    const iv = setInterval(() => {
      cur = Math.min(cur + step, val);
      el.textContent = cur.toLocaleString() + sfx;
      if (cur >= val) clearInterval(iv);
    }, 28);
  });
}
window.addEventListener('load', () => setTimeout(initCounters, 800));

/* ── Flash row interaction ──────────────────────────────────── */
function flash(el) {
  el.style.background = 'rgba(0,212,255,0.07)';
  setTimeout(() => el.style.background = '', 360);
}

/* ── Toast notification ─────────────────────────────────────── */
function showToast(msg, type) {
  const colors = { safe:'var(--green)', danger:'var(--red)', warn:'var(--warn)', info:'var(--accent)' };
  const t   = document.getElementById('toast');
  const col = colors[type] || colors.info;
  t.textContent       = msg;
  t.style.borderColor = col;
  t.style.color       = col;
  t.style.boxShadow   = `0 0 28px ${col}44`;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3200);
}

/* ── Shared result renderer (for hash + errors) ─────────────── */
function renderResult({ status, label, rows }) {
  const col = { safe:'var(--green)', danger:'var(--red)', warn:'var(--warn)', neutral:'var(--accent)' };
  let h = `<div class="r-header">
    <div class="r-dot ${status}"></div>
    <span class="r-status" style="color:${col[status]||col.neutral}">${label}</span>
  </div>`;
  rows.forEach(([k, v, cls = '']) => {
    h += `<div class="r-row"><span class="r-key">${k}</span><span class="r-val ${cls}">${v}</span></div>`;
  });
  return h;
}

/* ── Shared helpers ─────────────────────────────────────────── */
// Convert URL to VirusTotal URL ID (base64url, no padding)
function urlToId(url) {
  return btoa(url.replace(/\/$/, '')).replace(/=/g, '');
}

// Update progress text inside result box
function setStep(boxId, msg) {
  const el = document.getElementById(boxId + '_step');
  if (el) el.textContent = msg;
}

// Show animated loading state
function showLoading(boxId, msg = '// Connecting to VirusTotal...') {
  document.getElementById(boxId).innerHTML =
    `<div class="r-loading"></div>
     <span id="${boxId}_step" class="vt-progress">${msg}</span>`;
}

// Sleep helper
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ── Tool tab switching ─────────────────────────────────────── */
function switchTab(tabId, btn) {
  // Hide all panels
  document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
  // Deactivate all tab buttons
  document.querySelectorAll('.tool-tab').forEach(b => b.classList.remove('active'));
  // Show target panel + activate button
  const panel = document.getElementById('tab-' + tabId);
  if (panel) panel.classList.add('active');
  if (btn) btn.classList.add('active');
}
