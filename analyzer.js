/**
 * Password Analyzer
 * Powered by zxcvbn (Dropbox) — pattern-aware password strength estimation.
 * https://github.com/dropbox/zxcvbn
 */

const SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
const SCORE_COLORS = ['#E24B4A', '#D85A30', '#BA7517', '#639922', '#1D9E75'];

let eyeShown = false;

// ── Toggle password visibility ────────────────────────────────────────────────

function toggleEye() {
  eyeShown = !eyeShown;
  document.getElementById('pwd').type = eyeShown ? 'text' : 'password';
  document.getElementById('eye-icon').innerHTML = eyeShown
    ? `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8
         a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4
         c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19
         m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
       <line x1="1" y1="1" x2="23" y2="23"/>`
    : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
       <circle cx="12" cy="12" r="3"/>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtGuesses(g) {
  const fmt = (n) => n % 1 === 0 ? n.toFixed(0) : n.toFixed(1);
  if (g > 1e12) return fmt(g / 1e12) + 'T';
  if (g > 1e9)  return fmt(g / 1e9)  + 'B';
  if (g > 1e6)  return fmt(g / 1e6)  + 'M';
  if (g > 1e3)  return fmt(g / 1e3)  + 'K';
  return Math.round(g).toString();
}

function charCls(c) {
  if (/[A-Z]/.test(c)) return 'cb-u';
  if (/[a-z]/.test(c)) return 'cb-l';
  if (/\d/.test(c))    return 'cb-d';
  return 'cb-s';
}

// ── Match description ─────────────────────────────────────────────────────────

function matchTypeLabel(m) {
  const map = {
    dictionary:  'dict',
    spatial:     'keyboard',
    repeat:      'repeat',
    sequence:    'sequence',
    regex:       'pattern',
    date:        'date',
    bruteforce:  'brute-force',
  };
  return map[m.pattern] || m.pattern;
}

function matchTypeColorClass(pattern) {
  if (pattern === 'dictionary' || pattern === 'spatial') return 'tag-d';
  if (['repeat', 'sequence', 'date'].includes(pattern))  return 'tag-w';
  return 'tag-i';
}

function describeMatch(m) {
  const tok = `<span class="match-token">${escapeHtml(m.token)}</span>`;

  switch (m.pattern) {
    case 'dictionary': {
      const dict = (m.dictionary_name || '').replace(/_/g, ' ');
      let extras = '';
      if (m.l33t)     extras += ', leet substitution';
      if (m.reversed) extras += ', reversed';
      return `${tok} in <strong>${dict}</strong> wordlist, rank ${m.rank}${extras}`;
    }
    case 'spatial':
      return `${tok} keyboard walk on ${m.graph}`;
    case 'repeat':
      return `${tok} repeated char/sequence`;
    case 'sequence':
      return `${tok} common sequence (${m.sequence_name || ''})`;
    case 'date':
      return `${tok} resembles a date`;
    case 'bruteforce':
      return `${tok} no pattern detected`;
    default:
      return tok;
  }
}

// ── Build tags from zxcvbn result ─────────────────────────────────────────────

function buildTags(seq, pwd) {
  const has = (pattern, extra) => seq.some(m => {
    if (m.pattern !== pattern) return false;
    if (extra) return Object.entries(extra).every(([k, v]) => m[k] === v);
    return true;
  });

  const tags = [];

  if (has('dictionary', { dictionary_name: 'passwords' })) tags.push(['Common password', 'tag-d']);
  if (has('dictionary', { l33t: true }))                   tags.push(['Leet detected',   'tag-w']);
  if (has('dictionary', { reversed: true }))               tags.push(['Reversed word',   'tag-w']);
  if (has('spatial'))                                       tags.push(['Keyboard walk',   'tag-d']);
  if (has('repeat'))                                        tags.push(['Repeated chars',  'tag-w']);
  if (has('sequence'))                                      tags.push(['Sequential',      'tag-w']);
  if (has('date'))                                          tags.push(['Date pattern',    'tag-w']);

  if (pwd.length < 8)        tags.push(['Too short',      'tag-d']);
  else if (pwd.length < 12)  tags.push(['Moderate length','tag-w']);
  else                       tags.push(['Good length',    'tag-ok']);

  const types = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter(r => r.test(pwd)).length;
  if (types === 4)      tags.push(['All char types',     'tag-ok']);
  else if (types <= 2)  tags.push(['Limited char types', 'tag-w']);

  return tags;
}

// ── Render ────────────────────────────────────────────────────────────────────

let zxcvbnRetries = 0;

function analyze(pwd) {
  const el = document.getElementById('out');

  if (!pwd) {
    el.innerHTML = `
      <div class="empty">
        <div class="empty-mono">?*#!</div>
        <p>Type a password above to analyze</p>
      </div>`;
    return;
  }

  if (typeof zxcvbn === 'undefined') {
    if (zxcvbnRetries >= 10) {
      el.innerHTML = '<div class="empty"><p>Could not load zxcvbn engine. Check your connection and refresh.</p></div>';
      return;
    }
    zxcvbnRetries++;
    el.innerHTML = '<div class="empty"><p>Loading engine...</p></div>';
    setTimeout(() => analyze(document.getElementById('pwd').value), 300);
    return;
  }

  zxcvbnRetries = 0; // reset on successful load
  const res     = zxcvbn(pwd);
  const score   = res.score;
  const color   = SCORE_COLORS[score];
  const guesses = res.guesses;
  const entropy = +(Math.log2(Math.max(1, guesses))).toFixed(1);
  const entPct  = Math.min(100, (entropy / 80) * 100);
  const seq     = res.sequence || [];
  const fb      = res.feedback;

  // Character type counts
  const lower  = (pwd.match(/[a-z]/g) || []).length;
  const upper  = (pwd.match(/[A-Z]/g) || []).length;
  const digits = (pwd.match(/\d/g)    || []).length;
  const syms   = pwd.length - lower - upper - digits;
  const types  = [/[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z0-9]/].filter(r => r.test(pwd)).length;

  // Character frequency (for repeat highlighting)
  const freq = {};
  for (const c of pwd) freq[c] = (freq[c] || 0) + 1;

  // Score bars
  const barsHtml = Array.from({ length: 5 }, (_, i) =>
    `<div class="bar" style="${i <= score ? `background:${color}` : ''}"></div>`
  ).join('');

  // Tags
  const tags    = buildTags(seq, pwd);
  const tagsHtml = tags.map(([t, c]) => `<span class="tag ${c}">${t}</span>`).join('');

  // Pattern matches
  const matchesHtml = seq.map(m => `
    <div class="match-row">
      <span class="match-type ${matchTypeColorClass(m.pattern)}">${matchTypeLabel(m)}</span>
      <span class="match-desc">${describeMatch(m)}</span>
    </div>`
  ).join('');

  // Feedback / suggestions
  const suggestions = [];
  if (fb.warning) suggestions.push([fb.warning, 'danger']);
  (fb.suggestions || []).forEach(s => suggestions.push([s, 'warn']));
  if (!fb.warning && !(fb.suggestions || []).length) {
    suggestions.push(['No specific issues — strong password!', 'ok']);
  }

  const sugHtml = suggestions.map(([text, type]) => {
    const dotColor =
      type === 'danger' ? 'var(--danger-fg)' :
      type === 'warn'   ? 'var(--warn-fg)'   :
                          'var(--ok-fg)';
    return `
      <div class="sug-row">
        <div class="sug-dot" style="background:${dotColor}"></div>
        <span>${text}</span>
      </div>`;
  }).join('');

  // Character map
  const charHtml = Array.from(pwd).map(c => {
    const cls = freq[c] > 2 ? 'cb-r' : charCls(c);
    const display = c === ' ' ? '·' : escapeHtml(c);
    return `<span class="cb ${cls}">${display}</span>`;
  }).join('');

  // Length label
  const lenLabel =
    pwd.length < 8  ? 'too short' :
    pwd.length < 12 ? 'moderate'  :
    pwd.length < 16 ? 'good'      : 'excellent';

  el.innerHTML = `
    <div class="score-row">
      <span class="score-label" style="color:${color}">${SCORE_LABELS[score]}</span>
      <div class="bars">${barsHtml}</div>
    </div>

    <div class="ent-wrap">
      <div class="ent-row">
        <span>Estimated entropy (log₂ of zxcvbn guesses)</span>
        <span>${entropy} bits</span>
      </div>
      <div class="ent-bg">
        <div class="ent-fill" style="width:${entPct}%; background:${color}"></div>
      </div>
    </div>

    <div class="metrics">
      <div class="metric">
        <div class="m-label">length</div>
        <div class="m-val">${pwd.length}</div>
        <div class="m-sub">${lenLabel}</div>
      </div>
      <div class="metric">
        <div class="m-label">zxcvbn guesses</div>
        <div class="m-val">${fmtGuesses(guesses)}</div>
        <div class="m-sub">pattern-aware estimate</div>
      </div>
      <div class="metric">
        <div class="m-label">char types</div>
        <div class="m-val">${types}/4</div>
        <div class="m-sub">${lower}l ${upper}u ${digits}d ${syms}s</div>
      </div>
    </div>

    <div class="section">
      <div class="sec-title">Pattern analysis</div>
      <div class="tags" style="margin-bottom:${matchesHtml ? '10px' : '0'}">${tagsHtml}</div>
      ${matchesHtml ? `<div>${matchesHtml}</div>` : ''}
    </div>

    <div class="section">
      <div class="sec-title">zxcvbn feedback</div>
      ${sugHtml}
    </div>

    <div class="section">
      <div class="sec-title">Character map</div>
      <div class="char-map">${charHtml}</div>
      <div class="legend">
        <div class="leg"><div class="leg-dot cb-l"></div>lowercase</div>
        <div class="leg"><div class="leg-dot cb-u"></div>uppercase</div>
        <div class="leg"><div class="leg-dot cb-d"></div>digit</div>
        <div class="leg"><div class="leg-dot cb-s"></div>symbol</div>
        <div class="leg"><div class="leg-dot cb-r"></div>repeated 3+</div>
      </div>
    </div>
  `;
}
