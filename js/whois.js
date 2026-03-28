/* ================================================================
   whois.js — WHOIS / RDAP Lookup
   Nguồn theo thứ tự:
     1. CentralNIC  (qua CF Worker — cần proxy vì CORS)
     2. RDAP Identity Digital  (direct, CORS-friendly)
     3. RDAP Verisign           (direct, CORS-friendly)
     4. rdap.org fallback       (direct, universal)
================================================================ */
'use strict';

async function checkWhois() {
  const raw = document.getElementById('whoisInput').value.trim();
  const btn = document.getElementById('whoisBtn');
  const box = document.getElementById('whoisResult');

  if (!raw) { showToast('// Please enter a domain name', 'warn'); return; }

  // Normalize domain
  let domain = raw
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .split('/')[0].split('?')[0]
    .toLowerCase().trim();

  if (!domain || !domain.includes('.')) {
    showToast('// Invalid domain — e.g. example.com', 'danger');
    return;
  }

  btn.disabled = true;
  btn.textContent = '...';
  box.innerHTML = `<div class="r-loading"></div>
    <span id="whoisResult_step" class="vt-progress">// Querying CentralNIC WHOIS...</span>`;

  try {
    // ── Source 1: CentralNIC via Worker ──────────────────────
    let data = null;
    let source = '';

    setStep('whoisResult', '// Source 1/4 — CentralNIC WHOIS...');
    try {
      const cn = await fetch(`${VT}/../whois/centralnic?domain=${encodeURIComponent(domain)}`);
      if (cn.ok) {
        const cj = await cn.json();
        if (cj.raw && cj.raw.includes('Domain Name')) {
          data = parseCentralNIC(cj.raw, domain);
          source = 'CentralNIC';
        }
      }
    } catch(_) {}

    // ── Source 2: RDAP Identity Digital ──────────────────────
    if (!data) {
      setStep('whoisResult', '// Source 2/4 — RDAP Identity Digital...');
      try {
        const r = await fetch(`https://rdap.identitydigital.services/rdap/domain/${domain}`);
        if (r.ok) { data = parseRDAP(await r.json(), domain); source = 'RDAP Identity Digital'; }
      } catch(_) {}
    }

    // ── Source 3: RDAP Verisign ───────────────────────────────
    if (!data) {
      setStep('whoisResult', '// Source 3/4 — RDAP Verisign...');
      try {
        const r = await fetch(`https://rdap.verisign.com/com/v1/domain/${domain}`);
        if (r.ok) { data = parseRDAP(await r.json(), domain); source = 'RDAP Verisign'; }
      } catch(_) {}
    }

    // ── Source 4: rdap.org universal fallback ─────────────────
    if (!data) {
      setStep('whoisResult', '// Source 4/4 — rdap.org fallback...');
      try {
        const r = await fetch(`https://rdap.org/domain/${domain}`);
        if (r.status === 404) {
          box.innerHTML = renderResult({
            status: 'neutral', label: 'NOT FOUND',
            rows: [
              ['DOMAIN', domain],
              ['STATUS', 'Domain not found in any WHOIS/RDAP source. It may be unregistered.', 'warn'],
            ]
          });
          return;
        }
        if (r.ok) { data = parseRDAP(await r.json(), domain); source = 'rdap.org'; }
      } catch(_) {}
    }

    if (!data) throw new Error('No WHOIS data found from any source');

    setStep('whoisResult', '// Rendering results...');
    renderWhoisResult(box, data, domain, source);

  } catch (err) {
    box.innerHTML = renderResult({
      status: 'warn', label: 'ERROR',
      rows: [
        ['DOMAIN', domain],
        ['ERROR',  err.message, 'warn'],
        ['TIP',    'Try a .com / .net / .org domain. Some ccTLDs are not supported by RDAP.'],
      ]
    });
  } finally {
    btn.disabled = false;
    btn.textContent = 'LOOKUP';
  }
}

/* ── Parse CentralNIC raw text ───────────────────────────────── */
function parseCentralNIC(raw, domain) {
  const get = (keys) => {
    for (const k of keys) {
      const m = raw.match(new RegExp(k + '\\s*:\\s*(.+)', 'im'));
      if (m) return m[1].trim();
    }
    return 'N/A';
  };
  const getAll = (key) => {
    const matches = [...raw.matchAll(new RegExp(key + '\\s*:\\s*(.+)', 'gim'))];
    return matches.map(m => m[1].trim()).join(', ') || 'N/A';
  };

  return {
    domainName:    get(['Domain Name']),
    registrar:     get(['Registrar(?! WHOIS| URL| IANA| Abuse)']),
    registrarUrl:  get(['Registrar URL']),
    registrarIANA: get(['Registrar IANA ID']),
    abuseEmail:    get(['Registrar Abuse Contact Email', 'Registrar Abuse Contact E-mail']),
    abusePhone:    get(['Registrar Abuse Contact Phone', 'Registrar Abuse Contact Telephone']),
    created:       get(['Creation Date']),
    updated:       get(['Updated Date']),
    expires:       get(['Registry Expiry Date', 'Registrar Registration Expiration Date']),
    status:        getAll('Domain Status'),
    nameservers:   getAll('Name Server'),
    dnssec:        get(['DNSSEC']),
    registrant:    'N/A (GDPR redacted)',
    raw,
  };
}

/* ── Parse RDAP JSON ─────────────────────────────────────────── */
function parseRDAP(json, domain) {
  const getEnt = (role) => json.entities?.find(e => e.roles?.includes(role));
  const getVcard = (ent, field) => ent?.vcardArray?.[1]?.find(v => v[0] === field)?.[3] || 'N/A';
  const getDate = (action) => json.events?.find(e => e.eventAction === action)?.eventDate || null;
  const fmt = d => d ? new Date(d).toUTCString() : 'N/A';

  const reg = getEnt('registrar');
  const abuseEnt = getEnt('abuse') || reg?.entities?.find(e => e.roles?.includes('abuse'));

  return {
    domainName:    (json.ldhName || domain).toUpperCase(),
    registrar:     getVcard(reg, 'fn'),
    registrarUrl:  reg?.links?.find(l => l.rel === 'related')?.href || 'N/A',
    registrarIANA: reg?.publicIds?.find(p => p.type?.includes('IANA'))?.identifier || 'N/A',
    abuseEmail:    getVcard(abuseEnt, 'email'),
    abusePhone:    getVcard(abuseEnt, 'tel'),
    created:       fmt(getDate('registration')),
    updated:       fmt(getDate('last changed')),
    expires:       fmt(getDate('expiration')),
    status:        (json.status || []).join(', ') || 'N/A',
    nameservers:   (json.nameservers || []).map(n => n.ldhName || n.unicodeName || '').filter(Boolean).join(', ') || 'N/A',
    dnssec:        json.secureDNS?.delegationSigned ? 'Signed' : json.secureDNS?.delegationSigned === false ? 'Not signed' : 'N/A',
    registrant:    getVcard(getEnt('registrant'), 'fn'),
    raw:           null,
  };
}

/* ── Render WHOIS result card ────────────────────────────────── */
function renderWhoisResult(box, d, domain, source) {
  // Flag suspicious statuses
  const suspicious = ['serverHold','clientHold','pendingDelete','redemptionPeriod'];
  const flagged = d.status !== 'N/A' && suspicious.some(s => d.status.toLowerCase().includes(s.toLowerCase()));

  // Age warning
  let ageWarn = '', ageDays = null;
  if (d.created && d.created !== 'N/A') {
    const dt = new Date(d.created);
    if (!isNaN(dt)) {
      ageDays = Math.floor((Date.now() - dt) / 86400000);
    }
  }

  let status = 'safe', label = 'REGISTERED — ACTIVE';
  if (flagged)           { status = 'warn';   label = 'REGISTERED — FLAGGED STATUS'; }
  if (ageDays !== null && ageDays < 30) {
    status = 'warn'; label = `REGISTERED — NEW DOMAIN (${ageDays}d old)`;
    ageWarn = `Only ${ageDays} days old — newly registered domains are frequently used in abuse campaigns.`;
  }

  const rows = [
    ['DOMAIN',       d.domainName],
    ['REGISTRAR',    d.registrar],
    ['REGISTRAR URL',d.registrarUrl],
    ['IANA ID',      d.registrarIANA],
    ['REGISTRANT',   d.registrant],
    ['ABUSE EMAIL',  d.abuseEmail],
    ['ABUSE PHONE',  d.abusePhone],
    ['STATUS',       d.status, flagged ? 'warn' : ''],
    ['CREATED',      d.created],
    ['UPDATED',      d.updated],
    ['EXPIRES',      d.expires],
    ['NAMESERVERS',  d.nameservers],
    ['DNSSEC',       d.dnssec],

  ];

  if (ageWarn) rows.push(['⚠ AGE WARNING', ageWarn, 'warn']);

  box.innerHTML = renderResult({ status, label, rows });

  // Show raw toggle if CentralNIC
  if (d.raw) {
    box.innerHTML += `
      <div style="margin-top:12px">
        <button onclick="toggleRaw(this)" class="t-btn" style="font-size:10px;padding:6px 14px">
          SHOW RAW WHOIS
        </button>
        <pre id="whoisRaw" style="display:none;margin-top:10px;font-family:var(--mono);font-size:10px;color:var(--dim);white-space:pre-wrap;line-height:1.6;border-top:1px solid var(--border);padding-top:12px">${escHtml(d.raw)}</pre>
      </div>`;
  }
}

function toggleRaw(btn) {
  const pre = document.getElementById('whoisRaw');
  if (!pre) return;
  const show = pre.style.display === 'none';
  pre.style.display = show ? 'block' : 'none';
  btn.textContent   = show ? 'HIDE RAW WHOIS' : 'SHOW RAW WHOIS';
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
