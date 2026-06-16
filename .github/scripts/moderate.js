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

// ── Gibberish/entropy constants — tune these to adjust strictness ─────────────
const GIBBERISH_MIN_WORD_LEN      = 5;    // only test words with at least this many alpha chars
const GIBBERISH_MAX_WORD_LEN      = 20;   // any single alpha token longer than this is suspicious
const GIBBERISH_MIN_VOWEL_RATIO   = 0.12; // a plausible word must be >=12% vowels (y counts)
const GIBBERISH_MAX_CONSONANT_RUN = 6;    // reject a word with this many consecutive non-vowels
const GIBBERISH_WORD_FAIL_RATIO   = 0.40; // reject body if >=40% of tested words are gibberish

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

  // Repeated-character spam — checked on both body AND name
  if (/(.)\1{7,}/.test(body)) {
    return { pass: false, reason: 'repeated characters in body' };
  }
  if (/(.)\1{4,}/.test(name)) {
    return { pass: false, reason: 'repeated characters in name' };
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

  // Gibberish/entropy floor — catches keysmash and mixed-case noise like
  // "ahfghaodfhlaieufHa;iofhbvEJcFKLEf". Tests words >= GIBBERISH_MIN_WORD_LEN
  // alpha chars; rejects the body if >= GIBBERISH_WORD_FAIL_RATIO of them fail.
  const bodyWords = body.trim().split(/\s+/);
  const checkedWords = bodyWords.filter(
    w => w.replace(/[^a-z]/gi, '').length >= GIBBERISH_MIN_WORD_LEN
  );
  if (checkedWords.length > 0) {
    const failCount = checkedWords.filter(isWordGibberish).length;
    if (failCount / checkedWords.length >= GIBBERISH_WORD_FAIL_RATIO) {
      return { pass: false, reason: 'gibberish content' };
    }
  }

  return { pass: true, reason: 'ok' };
}

// Returns true if a single word token looks like gibberish.
// 'y' is treated as a vowel to avoid false-positives on words like "rhythm".
function isWordGibberish(word) {
  const w = word.toLowerCase().replace(/[^a-z]/g, '');
  if (w.length < GIBBERISH_MIN_WORD_LEN) return false;

  // Any single alpha token longer than GIBBERISH_MAX_WORD_LEN is suspicious —
  // genuine English words are nearly never this long.
  if (w.length > GIBBERISH_MAX_WORD_LEN) return true;

  const VOWELS = new Set(['a', 'e', 'i', 'o', 'u', 'y']);
  const vowelCount = Array.from(w).filter(c => VOWELS.has(c)).length;
  if (vowelCount / w.length < GIBBERISH_MIN_VOWEL_RATIO) return true;

  // Consonant-run check
  let maxRun = 0, run = 0;
  for (const c of w) {
    run = VOWELS.has(c) ? 0 : run + 1;
    if (run > maxRun) maxRun = run;
  }
  return maxRun >= GIBBERISH_MAX_CONSONANT_RUN;
}
