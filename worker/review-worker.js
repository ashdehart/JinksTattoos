// SECURITY NOTE: CORS headers are a browser hint, not an access control.
// Any client (curl, scripts, bots) can omit or spoof the Origin header.
// Real abuse prevention comes from: (1) honeypot field, (2) timing check,
// (3) KV rate limiting. CORS is configured correctly but not relied upon
// for security decisions.

// ── Configuration ────────────────────────────────────────────────────────────
// Hardcoded — not derived from the incoming Origin header.
// Change this to your actual Neocities URL after deploying.
const ALLOWED_ORIGIN = 'https://YOUR-SITE.neocities.org';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

// Rate limit: max submissions per window per IP
const RATE_LIMIT_MAX    = 3;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour in ms

// Minimum elapsed ms since page load before accepting a submission
const MIN_ELAPSED_MS = 3000;

// ── Entry point ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: CORS_HEADERS });
    }

    // ── Parse body ────────────────────────────────────────────────────────────
    let payload;
    try {
      payload = await request.json();
    } catch {
      return jsonError(400, 'Bad request');
    }

    const { name, rating, body, loadedAt, website } = payload;

    // ── Honeypot check ────────────────────────────────────────────────────────
    // Real users never fill this field. Return a generic 400 without explanation
    // so automated tooling cannot distinguish it from a validation error.
    if (website) {
      return jsonError(400, 'Bad request');
    }

    // ── Timing check ─────────────────────────────────────────────────────────
    // Reject submissions that arrive under 3 seconds after page load.
    const elapsed = Date.now() - parseInt(loadedAt, 10);
    if (!loadedAt || isNaN(elapsed) || elapsed < MIN_ELAPSED_MS) {
      return jsonError(400, 'Bad request');
    }

    // ── Input validation ─────────────────────────────────────────────────────
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 80) {
      return jsonError(400, 'Invalid name');
    }
    const ratingInt = parseInt(rating, 10);
    if (isNaN(ratingInt) || ratingInt < 1 || ratingInt > 5) {
      return jsonError(400, 'Invalid rating');
    }
    if (typeof body !== 'string' || body.trim().length < 10 || body.length > 800) {
      return jsonError(400, 'Invalid review body');
    }

    // ── Input sanitization ────────────────────────────────────────────────────
    const safeName = stripHtml(name.trim());
    const safeBody = stripHtml(body.trim());

    // ── Rate limiting (second layer) ──────────────────────────────────────────
    // Read visitor IP from CF-Connecting-IP — set by Cloudflare infrastructure,
    // not spoofable by the client (unlike X-Forwarded-For).
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ipKey = 'rl:' + (await hashString(ip));

    const limitResult = await checkRateLimit(env.RATE_LIMIT_KV, ipKey);
    if (!limitResult.allowed) {
      return new Response(
        JSON.stringify({ error: 'Too many requests — please try again later.' }),
        { status: 429, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Retry-After': '3600' } }
      );
    }

    // ── Commit to GitHub ──────────────────────────────────────────────────────
    const timestamp  = Date.now();
    const randomHex  = Array.from(crypto.getRandomValues(new Uint8Array(4)))
                           .map(b => b.toString(16).padStart(2, '0'))
                           .join('');
    const filename   = `${timestamp}-${randomHex}.json`;

    const reviewData = {
      id:   `${timestamp}-${randomHex}`,
      name: safeName,
      rating: ratingInt,
      body: safeBody,
      date: new Date().toISOString().slice(0, 10),
      submittedAt: new Date().toISOString(),
    };

    const fileContent = btoa(JSON.stringify(reviewData, null, 2));

    const githubRes = await fetch(
      `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/reviews/pending/${filename}`,
      {
        method: 'PUT',
        headers: {
          'Authorization': `token ${env.GITHUB_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'jinks-review-worker',
        },
        body: JSON.stringify({
          message: `review: add pending submission ${filename}`,
          content: fileContent,
        }),
      }
    );

    if (!githubRes.ok) {
      const errText = await githubRes.text();
      console.error('GitHub API error:', githubRes.status, errText);
      return jsonError(502, 'Could not save review — please try again.');
    }

    return new Response(
      JSON.stringify({ ok: true, message: 'Review submitted — thank you!' }),
      { status: 201, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }
    );
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function jsonError(status, message) {
  return new Response(
    JSON.stringify({ error: message }),
    { status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }
  );
}

// Strip HTML tags — prevents stored XSS in the JSON payload
function stripHtml(str) {
  return str.replace(/<[^>]*>/g, '');
}

// SHA-256 hash of the IP string for the KV key (avoids storing raw IPs)
async function hashString(str) {
  const encoded = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 32); // 32 hex chars is plenty for a KV key
}

// KV-based rate limiter: allows RATE_LIMIT_MAX requests per RATE_LIMIT_WINDOW
async function checkRateLimit(kv, key) {
  const now = Date.now();
  let record = { count: 0, windowStart: now };

  try {
    const stored = await kv.get(key, 'json');
    if (stored && (now - stored.windowStart) < RATE_LIMIT_WINDOW) {
      record = stored;
    }
  } catch {
    // If KV is unavailable, fail open rather than blocking all users
    return { allowed: true };
  }

  if (record.count >= RATE_LIMIT_MAX) {
    return { allowed: false };
  }

  record.count += 1;
  // TTL matches the window so the key expires automatically
  await kv.put(key, JSON.stringify(record), { expirationTtl: Math.ceil(RATE_LIMIT_WINDOW / 1000) });
  return { allowed: true };
}
