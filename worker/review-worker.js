// SECURITY NOTE: CORS headers are a browser hint, not an access control.
// Any client (curl, scripts, bots) can omit or spoof the Origin header.
// Real abuse prevention comes from: (1) honeypot field, (2) timing check,
// (3) KV rate limiting. CORS is configured correctly but not relied upon
// for security decisions.

// ── Configuration ────────────────────────────────────────────────────────────
// Both origins are hardcoded. The incoming Origin header is checked against
// this list only to decide which value to reflect in the CORS response —
// it is not used as a security gate.
const ALLOWED_ORIGINS = [
  'https://jinkstattoos.shop',
  'https://jinksdevsite.neocities.org',
  'http://127.0.0.1:5500', // Live Server local dev
];

function corsHeaders(requestOrigin) {
  // Reflect the exact origin if it's in the allowlist; fall back to prod.
  const origin = ALLOWED_ORIGINS.includes(requestOrigin)
    ? requestOrigin
    : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// Rate limit: max submissions per window per IP
const RATE_LIMIT_MAX    = 3;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour in ms

// Minimum elapsed ms since page load before accepting a submission
const MIN_ELAPSED_MS = 3000;
// Browser clocks can run slightly ahead of Cloudflare's servers.
// Tolerate up to this many ms of skew before treating loadedAt as invalid.
const CLOCK_SKEW_TOLERANCE_MS = 30000;

// Workers AI model for pre-moderation
const AI_MODEL = '@cf/meta/llama-3.2-3b-instruct';

// ── Entry point ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: corsHeaders(origin) });
    }

    // ── Parse body ────────────────────────────────────────────────────────────
    let payload;
    try {
      payload = await request.json();
    } catch {
      return jsonError(400, 'Bad request', origin);
    }

    const { name, rating, body, loadedAt, website } = payload;

    // ── Honeypot check ────────────────────────────────────────────────────────
    // Real users never fill this field. Return a generic 400 without explanation
    // so automated tooling cannot distinguish it from a validation error.
    if (website) {
      return jsonError(400, 'Bad request', origin);
    }

    // ── Timing check ─────────────────────────────────────────────────────────
    // Reject submissions that arrive under 3 seconds after page load.
    // CLOCK_SKEW_TOLERANCE_MS accounts for browser clocks running slightly ahead
    // of Cloudflare's infrastructure (~10s observed; 30s tolerance for headroom).
    const elapsed = Date.now() - parseInt(loadedAt, 10);
    if (!loadedAt || isNaN(elapsed) || elapsed < MIN_ELAPSED_MS - CLOCK_SKEW_TOLERANCE_MS) {
      return jsonError(400, 'Bad request', origin);
    }

    // ── Input validation ─────────────────────────────────────────────────────
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 80) {
      return jsonError(400, 'Invalid name', origin);
    }
    const ratingInt = parseInt(rating, 10);
    if (isNaN(ratingInt) || ratingInt < 1 || ratingInt > 5) {
      return jsonError(400, 'Invalid rating', origin);
    }
    if (typeof body !== 'string' || body.trim().length < 10 || body.length > 800) {
      return jsonError(400, 'Invalid review body', origin);
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
        {
          status: 429,
          headers: {
            ...corsHeaders(origin),
            'Content-Type': 'application/json',
            'Retry-After': '3600',
          },
        }
      );
    }

    // ── Build review payload ──────────────────────────────────────────────────
    const timestamp = Date.now();
    const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(4)))
                          .map(b => b.toString(16).padStart(2, '0'))
                          .join('');
    const filename  = `${timestamp}-${randomHex}.json`;

    const reviewData = {
      id:          `${timestamp}-${randomHex}`,
      name:        safeName,
      rating:      ratingInt,
      body:        safeBody,
      date:        new Date().toISOString().slice(0, 10),
      submittedAt: new Date().toISOString(),
    };

    const fileContent = btoa(JSON.stringify(reviewData, null, 2));

    // ── Workers AI pre-filter ─────────────────────────────────────────────────
    // CRITICAL: any failure here (timeout, parse error, bad response, env.AI
    // unavailable) must fall through silently — AI never gates a submission.
    // Rejected reviews go to reviews/ai-rejected/ for manual audit; the
    // submitter always receives a 201 so they cannot probe the classifier.
    let aiRejected = false;
    try {
      const aiResponse = await env.AI.run(AI_MODEL, {
        messages: [
          {
            role: 'system',
            content:
              'You are a content moderator for a tattoo studio review page. ' +
              'Classify the review as genuine ("approve") or spam/abusive/nonsense ("reject"). ' +
              'Reply with only valid JSON: {"verdict":"approve"} or {"verdict":"reject"}.',
          },
          {
            role: 'user',
            content: `Name: ${safeName}\nReview: ${safeBody}`,
          },
        ],
        max_tokens: 30,
      });
      // Normalize the response to a string — different Workers AI models return
      // different shapes: { response: string }, { response: string[] } (token array),
      // OpenAI-compat choices[], or a plain string.
      let text = '';
      if (typeof aiResponse === 'string') {
        text = aiResponse;
      } else if (typeof aiResponse?.response === 'string') {
        text = aiResponse.response;
      } else if (Array.isArray(aiResponse?.response)) {
        text = aiResponse.response.join('');
      } else if (typeof aiResponse?.choices?.[0]?.message?.content === 'string') {
        text = aiResponse.choices[0].message.content;
      } else if (aiResponse != null) {
        text = JSON.stringify(aiResponse);
      }
      const match = text.trim().match(/\{[^}]*\}/);
      if (match) {
        const parsed = JSON.parse(match[0]);
        aiRejected = parsed.verdict === 'reject';
      }
    } catch (err) {
      // AI unavailable or response unparseable — fall through to pending write
      console.error('AI pre-filter error (falling through to pending):', err?.message);
    }

    if (aiRejected) {
      // Store for manual review; do not block the response on this write
      fetch(
        `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/reviews/ai-rejected/${filename}`,
        {
          method: 'PUT',
          headers: {
            'Authorization': `token ${env.GITHUB_TOKEN}`,
            'Content-Type': 'application/json',
            'User-Agent': 'jinks-review-worker',
          },
          body: JSON.stringify({
            message: `review: ai-rejected submission ${filename}`,
            content: fileContent,
          }),
        }
      ).then(r => {
        if (!r.ok) console.error('GitHub ai-rejected write failed:', r.status);
      }).catch(err => {
        console.error('GitHub ai-rejected write error:', err?.message);
      });

      return new Response(
        JSON.stringify({ ok: true, message: 'Review submitted — thank you!' }),
        {
          status: 201,
          headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
        }
      );
    }

    // ── Commit to GitHub (pending — passes to Action for moderation) ──────────
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
      return jsonError(502, 'Could not save review — please try again.', origin);
    }

    return new Response(
      JSON.stringify({ ok: true, message: 'Review submitted — thank you!' }),
      {
        status: 201,
        headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
      }
    );
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function jsonError(status, message, origin) {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status,
      headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    }
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
