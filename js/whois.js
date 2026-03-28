/* ================================================================
   whois.js — WHOIS / RDAP Domain Lookup
================================================================ */
'use strict';

const WHOIS_PROXY = 'https://vt-proxy.websentinel1990.workers.dev';

async function checkWhois() {
  const raw = document.getElementById('whoisInput').value.trim();
  const btn = document.getElementById('whoisBtn');
  const box = document.getElementById('whoisResult');

  if (!raw) { showToast('// Please enter a domain name', 'warn'); return; }

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
  showLoading('whoisResult', `// Querying WHOIS for ${domain}...`);

  try {
    let data = null;

    setStep('whoisResult', '// Querying WHOIS database...');
    try {
      const r1 = await fetch(`${WHOIS_PROXY}/whois/centralnic?domain=${encodeURIComponent(domain)}`);
      if (r1.ok) {
        const j = await r1.json();
        if (j.raw && j.raw.includes('Domain Name')) {
          data = parseCentralNIC(j.raw, domain);
        }
      }
    } catch(_) {}

    if (!data) {
      try {
        const r2 = await fetch(`https://rdap.identitydigital.services/rdap/domain/${domain}`);
        if (r2.ok) data = parseRDAP(await r2.json(), domain);
      } catch(_) {}
    }

    if (!data) {
      try {
        const r3 = await fetch(`https://rdap.verisign.com/com/v1/domain/${domain}`);
        if (r3.ok) data = parseRDAP(await r3.json(), domain);
      } catch(_) {}
    }

    if (!data) {
      try {
        const r4 = await fetch(`https://rdap.org/domain/${domain}`);
        if (r4.status === 404) {
          box.innerHTML = renderResult({
            status: 'neutral', label: 'NOT FOUND',
            rows: [
              ['DOMAIN', domain],
              ['STATUS', 'Domain not found. It may be unregistered or use an unsupported TLD.', 'warn'],
            ]
          });
          return;
        }
        if (r4.ok) data = parseRDAP(await r4.json(), domain);
      } catch(_) {}
    }

    if (!data) throw new Error('No registration data found for this domain');

    renderWhoisResult(box, data, domain);

  } catch (err) {
    box.innerHTML = renderResult({
      status: 'warn', label: 'ERROR',
      rows: [
        ['DOMAIN', domain],
        ['ERROR',  err.message, 'warn'],
        ['TIP',    'Some ccTLDs (.vn, .uk, etc.) may return limited data.'],
      ]
    });
  } finally {
    btn.disabled = false;
    btn.textContent = 'LOOKUP';
  }
}

/* ── Parse raw WHOIS text ────────────────────────────────────── */
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
    abusePhone:    get(['Registrar Abuse Contact Phone']),
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
  const getEnt  = (role) => json.entities?.find(e => e.roles?.includes(role));
  const getVcard= (ent, field) => ent?.vcardArray?.[1]?.find(v => v[0] === field)?.[3] || 'N/A';
  const getDate = (action) => json.events?.find(e => e.eventAction === action)?.eventDate || null;
  const fmt     = d => d ? new Date(d).toUTCString() : 'N/A';
  const reg     = getEnt('registrar');
  const abuse   = getEnt('abuse') || reg?.entities?.find(e => e.roles?.includes('abuse'));
  return {
    domainName:    (json.ldhName || domain).toUpperCase(),
    registrar:     getVcard(reg, 'fn'),
    registrarUrl:  reg?.links?.find(l => l.rel === 'related')?.href || 'N/A',
    registrarIANA: reg?.publicIds?.find(p => p.type?.includes('IANA'))?.identifier || 'N/A',
    abuseEmail:    getVcard(abuse, 'email'),
    abusePhone:    getVcard(abuse, 'tel'),
    created:       fmt(getDate('registration')),
    updated:       fmt(getDate('last changed')),
    expires:       fmt(getDate('expiration')),
    status:        (json.status || []).join(', ') || 'N/A',
    nameservers:   (json.nameservers || []).map(n => n.ldhName || '').filter(Boolean).join(', ') || 'N/A',
    dnssec:        json.secureDNS?.delegationSigned ? 'Signed' : json.secureDNS?.delegationSigned === false ? 'Not signed' : 'N/A',
    registrant:    getVcard(getEnt('registrant'), 'fn'),
    raw:           null,
  };
}

/* ── Render result ───────────────────────────────────────────── */
function renderWhoisResult(box, d, domain) {
  const suspicious = ['serverHold','clientHold','pendingDelete','redemptionPeriod'];
  const flagged    = d.status !== 'N/A' && suspicious.some(s => d.status.toLowerCase().includes(s.toLowerCase()));

  let ageDays = null;
  if (d.created && d.created !== 'N/A') {
    const dt = new Date(d.created);
    if (!isNaN(dt)) ageDays = Math.floor((Date.now() - dt) / 86400000);
  }

  let status = 'safe', label = 'REGISTERED — ACTIVE';
  if (flagged)                              { status = 'warn';   label = 'REGISTERED — FLAGGED STATUS'; }
  if (ageDays !== null && ageDays < 30)     { status = 'warn';   label = `REGISTERED — NEW DOMAIN (${ageDays}d old)`; }

  const rows = [
    ['DOMAIN',        d.domainName],
    ['REGISTRAR',     d.registrar],
    ['REGISTRAR URL', d.registrarUrl],
    ['IANA ID',       d.registrarIANA],
    ['REGISTRANT',    d.registrant],
    ['ABUSE EMAIL',   d.abuseEmail],
    ['ABUSE PHONE',   d.abusePhone],
    ['STATUS',        d.status, flagged ? 'warn' : ''],
    ['CREATED',       d.created],
    ['UPDATED',       d.updated],
    ['EXPIRES',       d.expires],
    ['NAMESERVERS',   d.nameservers],
    ['DNSSEC',        d.dnssec],
  ];

  if (ageDays !== null && ageDays < 30) {
    rows.push(['⚠ AGE WARNING', `Only ${ageDays} days old — newly registered domains are frequently used in abuse campaigns.`, 'warn']);
  }

  box.innerHTML = renderResult({ status, label, rows });
}


