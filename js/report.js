/* ================================================================
   report.js — Abuse report form submission
   Opens mailto: with structured report body
================================================================ */
'use strict';

function submitReport() {
  const domain   = document.getElementById('rDomain').value.trim();
  const type     = document.getElementById('rType').value;
  const behavior = document.getElementById('rBehavior').value.trim();

  // Validate required fields
  if (!domain || !type || !behavior) {
    showToast('// Required: domain, abuse type, and observed behavior', 'danger');
    return;
  }

  const subject = `[DNS Abuse Report] ${type.toUpperCase()} — ${domain}`;
  const body = [
    'THREATVECTOR INTELLIGENCE — ABUSE REPORT',
    '='.repeat(42),
    '',
    `DOMAIN:         ${domain}`,
    `ABUSE TYPE:     ${type}`,
    `REPORTER:       ${document.getElementById('rName').value  || 'Anonymous'}`,
    `CONTACT:        ${document.getElementById('rEmail').value || 'Not provided'}`,
    `ASSOCIATED IPs: ${document.getElementById('rIPs').value   || 'N/A'}`,
    `FIRST OBSERVED: ${document.getElementById('rDate').value  || 'Not specified'}`,
    '',
    'OBSERVED BEHAVIOR:',
    behavior,
    '',
    'EVIDENCE:',
    document.getElementById('rEvidence').value || 'None provided',
    '',
    'INDICATORS OF COMPROMISE:',
    document.getElementById('rIOCs').value || 'None provided',
    '',
    'ADDITIONAL NOTES:',
    document.getElementById('rNotes').value || 'None',
    '',
    '--',
    'Submitted via ThreatVector Intelligence portal',
    'threatvectorintelligence.com',
  ].join('\n');

  window.location.href =
    'mailto:abuse@threatvectorintelligence.com' +
    '?subject=' + encodeURIComponent(subject) +
    '&body='    + encodeURIComponent(body);

  showToast('// Report prepared — opening email client', 'safe');
}
