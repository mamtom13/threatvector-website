// ================================================================
//  ThreatVector Intelligence — Cloudflare Worker
//  VirusTotal API Proxy — bypasses CORS for browser-side calls
//
//  Routes:
//    GET  /vt/urls/{id}              → check cached URL report
//    POST /vt/urls                   → submit new URL for scanning
//    GET  /vt/analyses/{id}          → poll scan status
//    GET  /vt/urls/{id}/screenshot   → fetch website screenshot
//    GET  /vt/files/{hash}           → file/hash lookup
// ================================================================

const VT_KEY  = 'f4a9e2e8bce7ef662decc2a13bf96f5b7288d6b4dcf7833fd3e1c4b39359b985';
const VT_BASE = 'https://www.virustotal.com/api/v3';

// After domain is live, change '*' to 'https://threatvectorintelligence.com'
const CORS_ORIGIN = '*';

export default {
  async fetch(request) {

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    const url      = new URL(request.url);
    const endpoint = url.pathname.replace(/^\/vt\/?/, '').replace(/^\/+/, '');

    if (!endpoint) {
      return jsonResponse({ error: 'Missing endpoint. Use /vt/{endpoint}' }, 400);
    }

    try {
      // Screenshot — returns binary PNG
      if (endpoint.includes('/screenshot')) {
        return await proxyScreenshot(endpoint);
      }

      // POST — submit new URL
      if (request.method === 'POST') {
        return await proxyPost(endpoint, request);
      }

      // GET — all other endpoints
      return await proxyGet(endpoint);

    } catch (err) {
      return jsonResponse({ error: err.message }, 500);
    }
  }
};

// ── GET proxy ─────────────────────────────────────────────────
async function proxyGet(endpoint) {
  const res  = await fetch(`${VT_BASE}/${endpoint}`, {
    headers: { 'x-apikey': VT_KEY }
  });
  const data = await res.json();
  return jsonResponse(data, res.status);
}

// ── POST proxy (submit new URL) ────────────────────────────────
async function proxyPost(endpoint, request) {
  const body = await request.text();
  const res  = await fetch(`${VT_BASE}/${endpoint}`, {
    method:  'POST',
    headers: {
      'x-apikey':     VT_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const data = await res.json();
  return jsonResponse(data, res.status);
}

// ── Screenshot proxy (binary blob) ────────────────────────────
async function proxyScreenshot(endpoint) {
  const res = await fetch(`${VT_BASE}/${endpoint}`, {
    headers: { 'x-apikey': VT_KEY }
  });

  if (!res.ok) {
    return new Response(null, {
      status: res.status,
      headers: corsHeaders(),
    });
  }

  const blob = await res.arrayBuffer();
  return new Response(blob, {
    status: 200,
    headers: {
      'Content-Type':                'image/png',
      'Access-Control-Allow-Origin': CORS_ORIGIN,
    },
  });
}

// ── Helpers ───────────────────────────────────────────────────
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type':                'application/json',
      'Access-Control-Allow-Origin': CORS_ORIGIN,
    },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  CORS_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-apikey',
  };
}
