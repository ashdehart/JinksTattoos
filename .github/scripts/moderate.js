#!/usr/bin/env node
// Moderation script for Jinks Tattoos review pipeline.
// Called by the GitHub Action after a new file appears in reviews/pending/.
//
// What this script does:
//   1. Determines which files in reviews/pending/ were added in the most
//      recent commit (via git diff).
//   2. Validates every filename against a strict regex before touching it
//      (prevents path traversal or unexpected filenames reaching fs/shell).
//   3. Parses each file, runs the moderation check, and moves it to either
//      reviews/approved/ or reviews/rejected/ using Node fs (not shell git mv).
//   4. Regenerates reviews.json from all approved reviews.
//   5. Stages all changes with `git add -A` (no user-controlled data in the command).
//
// The Action workflow handles git commit + git push after this script exits.

'use strict';

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ── Paths ─────────────────────────────────────────────────────────────────────
const REPO_ROOT   = path.resolve(__dirname, '..', '..');
const PENDING_DIR = path.join(REPO_ROOT, 'reviews', 'pending');
const APPROVED_DIR = path.join(REPO_ROOT, 'reviews', 'approved');
const REJECTED_DIR = path.join(REPO_ROOT, 'reviews', 'rejected');
const OUTPUT_FILE  = path.join(REPO_ROOT, 'reviews.json');

// Ensure destination directories exist
[APPROVED_DIR, REJECTED_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ── Filename validation ───────────────────────────────────────────────────────
// Only process files that match the pattern the Worker produces:
//   {unix-timestamp}-{4-byte lowercase hex}.json
// Anything else is skipped and logged. This prevents path traversal and
// ensures no unsanitized filename ever reaches a shell command or fs call.
const VALID_FILENAME = /^[0-9]+-[a-f0-9]+\.json$/;

// ── Find files added in this push ────────────────────────────────────────────
// git diff --name-only HEAD^ HEAD gives us the list of changed files in the
// commit that triggered this workflow run.
let changedFiles;
try {
  changedFiles = execSync('git diff --name-only HEAD^ HEAD', { encoding: 'utf8' })
    .split('\n')
    .map(f => f.trim())
    .filter(f => f.startsWith('reviews/pending/') && f.endsWith('.json'));
} catch (err) {
  console.error('Could not determine changed files:', err.message);
  process.exit(1);
}

if (changedFiles.length === 0) {
  console.log('No pending review files to process.');
  process.exit(0);
}

console.log(`Processing ${changedFiles.length} pending review(s)…`);

// ── Process each file ─────────────────────────────────────────────────────────
for (const relPath of changedFiles) {
  const basename = path.basename(relPath);

  // Strict filename validation — skip and log anything unexpected
  if (!VALID_FILENAME.test(basename)) {
    console.warn(`SKIP: unexpected filename "${basename}" — does not match expected pattern`);
    continue;
  }

  const srcPath = path.join(REPO_ROOT, relPath);

  if (!fs.existsSync(srcPath)) {
    console.warn(`SKIP: file not found at ${srcPath}`);
    continue;
  }

  // Parse JSON
  let review;
  try {
    review = JSON.parse(fs.readFileSync(srcPath, 'utf8'));
  } catch (err) {
    console.warn(`SKIP: could not parse ${basename}: ${err.message}`);
    const dest = path.join(REJECTED_DIR, basename);
    fs.renameSync(srcPath, dest);
    continue;
  }

  // Run moderation check
  const result = moderate({ name: review.name, body: review.body });

  if (result.pass) {
    console.log(`APPROVE: ${basename}`);
    fs.renameSync(srcPath, path.join(APPROVED_DIR, basename));
  } else {
    console.log(`REJECT: ${basename} — ${result.reason}`);
    fs.renameSync(srcPath, path.join(REJECTED_DIR, basename));
  }
}

// ── Regenerate reviews.json ───────────────────────────────────────────────────
// Read every approved review (filenames re-validated), sort newest-first,
// write the aggregated file.
const approvedFiles = fs.existsSync(APPROVED_DIR)
  ? fs.readdirSync(APPROVED_DIR).filter(f => VALID_FILENAME.test(f))
  : [];

const reviews = approvedFiles
  .map(filename => {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(APPROVED_DIR, filename), 'utf8'));
      return data;
    } catch {
      console.warn(`Could not parse approved file ${filename} — skipping`);
      return null;
    }
  })
  .filter(Boolean)
  // Sort by the numeric timestamp in the filename (newest first)
  .sort((a, b) => {
    const tsA = parseInt((a.id || '0').split('-')[0], 10);
    const tsB = parseInt((b.id || '0').split('-')[0], 10);
    return tsB - tsA;
  });

const output = {
  updated: new Date().toISOString(),
  reviews,
};

fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2) + '\n', 'utf8');
console.log(`reviews.json updated — ${reviews.length} approved review(s).`);

// Stage all changes (moves + reviews.json).
// No user-controlled data in this command.
execSync('git add -A', { cwd: REPO_ROOT, stdio: 'inherit' });

// ── Moderation logic ──────────────────────────────────────────────────────────
// Returns { pass: boolean, reason: string }.
//
// SWAP POINT: replace the word-list check inside this function with an
// AI API call (e.g. Claude / OpenAI moderation endpoint) without touching
// any of the file-handling or Action workflow code above.
function moderate({ name, body }) {
  if (!name || !body) {
    return { pass: false, reason: 'missing fields' };
  }

  // Length guards (mirror Worker validation)
  if (name.length > 80) {
    return { pass: false, reason: 'name too long' };
  }
  if (body.trim().length < 10) {
    return { pass: false, reason: 'body too short' };
  }

  // All-caps spam signal (allow short all-caps words but reject all-caps bodies)
  const words = body.trim().split(/\s+/);
  if (words.length > 3 && body === body.toUpperCase()) {
    return { pass: false, reason: 'all-caps body' };
  }

  // Repeated-character spam (e.g. "aaaaaaaaa", "!!!!!!!!!")
  if (/(.)\1{7,}/.test(body)) {
    return { pass: false, reason: 'repeated characters' };
  }

  // Profanity word list — whole-word, case-insensitive
  // Add or remove words as needed; keep this list reasonably short and
  // replace with an API call once volume warrants it.
  const PROFANITY = [
    'fuck', 'shit', 'asshole', 'bitch', 'cunt', 'cock', 'dick', 'pussy',
    'faggot', 'nigger', 'nigga', 'whore', 'slut',
  ];
  const combined = (name + ' ' + body).toLowerCase();
  for (const word of PROFANITY) {
    const re = new RegExp(`\\b${word}\\b`);
    if (re.test(combined)) {
      return { pass: false, reason: `profanity: ${word}` };
    }
  }

  // URL spam signal — more than one URL in the body is suspicious
  const urlCount = (body.match(/https?:\/\//gi) || []).length;
  if (urlCount > 1) {
    return { pass: false, reason: 'multiple URLs' };
  }

  return { pass: true, reason: 'ok' };
}
