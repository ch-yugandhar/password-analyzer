# Password Analyzer

![GitHub Pages](https://img.shields.io/badge/hosted-GitHub%20Pages-222?logo=github)
![zxcvbn](https://img.shields.io/badge/engine-zxcvbn%204.4.2-blue)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A client-side password strength analyzer built for security research and portfolio purposes. Powered by [zxcvbn](https://github.com/dropbox/zxcvbn) — the same engine used by Dropbox — for realistic, pattern-aware strength estimation.

**No password ever leaves your browser.** Everything runs locally in JavaScript.

## Live Demo

**[ch-yugandhar.github.io/password-analyzer](https://ch-yugandhar.github.io/password-analyzer)**

---

## What it does

Most password strength meters use naive entropy math — they count character types and length and call it done. That's why they rate `P@ssw0rd1!` as strong, even though it's one of the first passwords any attacker tries.

This tool uses zxcvbn, which models how a real attacker thinks:

- Checks against dictionaries of millions of common passwords
- Detects keyboard walks (`qwerty`, `asdfgh`, `zxcvbn`)
- Reverses leet substitutions (`p@ssw0rd` → `password`) before checking
- Catches reversed words (`drowssap`)
- Identifies date patterns, repeated characters, sequential sequences
- Returns an honest guess count — not a fabricated "crack time"

---

## Features

- **Pattern-aware scoring** — zxcvbn guess estimate, not pool-size entropy
- **Entropy bar** — log₂ of guess count, scales meaningfully with real strength
- **Detailed pattern breakdown** — shows exactly which token matched, which wordlist, and why
- **Character map** — per-character color coding (lowercase / uppercase / digit / symbol / repeated)
- **zxcvbn feedback** — direct warnings and suggestions from the engine
- **Dark mode** — fully supported, respects system preference
- **Zero dependencies** — no npm, no build step, no framework
- **Fully client-side** — no server, no data collection, no tracking

---

## Why crack time estimates are not shown

Crack time depends on variables this tool cannot know:

- Which hash algorithm was used (bcrypt, MD5, NTLM, Argon2, plain text...)
- Attacker hardware (single GPU vs distributed cluster)
- Whether the hash was salted
- Whether the attacker uses wordlists, rules, or brute-force

Showing "cracked in 3 days" sounds precise but is meaningless without that context. The zxcvbn guess count is the honest signal — a higher guess count means more work for an attacker, regardless of their hardware.

---

## Project structure

```
password-analyzer/
├── index.html    — markup, meta tags, script loading
├── style.css     — design tokens, dark mode, all component styles
├── analyzer.js   — zxcvbn integration, pattern logic, render
└── README.md
```

No build step. No bundler. Open `index.html` and it works.

---

## Run locally

```bash
git clone https://github.com/ch-yugandhar/password-analyzer.git
cd password-analyzer
start index.html     # Windows
open index.html      # macOS
xdg-open index.html  # Linux
```

---

## Dependencies

| Package | Version | How it loads |
|---------|---------|--------------|
| zxcvbn  | 4.4.2   | jsDelivr CDN |

zxcvbn is the only external dependency and loads once on page open. All analysis runs locally after that — no further network requests.

---

## Security notes

- Passwords are processed entirely in the browser
- zxcvbn runs locally after the initial CDN load
- No analytics, no tracking, no external requests during analysis
- To run fully offline: download `zxcvbn.js` locally and update the `<script>` src in `index.html`

---

## Built with

- Vanilla JavaScript (ES6+)
- CSS custom properties with automatic dark mode
- [zxcvbn](https://github.com/dropbox/zxcvbn) by Dropbox

---

## License

MIT — free to use, modify, and distribute.
