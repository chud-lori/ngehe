# DESIGN.md — ngehe landing page

Direction for the GitHub Pages landing page (`docs/index.html`). This file is
derived from decisions the repo already made, not invented. Every claim cites
its source. Anything that could not be sourced is parked under "Open" for the
owner to answer.

## Identity

ngehe is a single-binary Go penetration-testing CLI for authorized
assessments, Hack The Box machines, and CTFs. It discovers a target's attack
surface (web plus non-HTTP services) and tests for the OWASP Top 10 alongside
the common HTB vectors: SSH, FTP, SMB, LDAP/AD, Kerberos, default credentials.
Every finding carries a concrete next-step so the operator can chain it toward
a shell.

- Source: README.md:1-9 ("Pentest CLI for authorized assessments, HTB boxes, and CTFs...")
- Source: cmd/root.go:11-27 (command long-help)
- The landing page doubles as the tool's reference, not a brochure (owner direction).

## Personality

Practitioner to practitioner. Blunt, technical, evidence-first, no marketing
gloss. The voice states what a command does and shows the real flag, not a
value proposition.

- Source (voice sample): docs/index.html:275 "No Python venv hell, no plugin sprawl, no GUI tax."
- Source (voice sample): README.md:9 "Status: alpha. Useful in real engagements, not yet a finished product."

## Palette

Dark, terminal-adjacent. Taken verbatim from the existing stylesheet.

| Token | Value | Role |
|---|---|---|
| `--bg` | `#0b0f14` | page background |
| `--bg-2` | `#0f141c` | alternate ground |
| `--panel` | `#121925` | card surface |
| `--panel-2` | `#182232` | table header / filename bar |
| `--border` | `#1f2a3a` | hairlines |
| `--code-bg` | `#0a0e14` | code surface |
| `--text` | `#e6edf3` | body text |
| `--muted` | `#8b98a5` | secondary text |
| `--accent` | `#7ee787` | primary accent (green) |
| `--accent-2` | `#58a6ff` | links (blue) |
| `--warn` | `#f0883e` | high severity (orange) |
| `--crit` | `#ff7b72` | critical severity (red) |

- Source: docs/index.html:20-33 (`:root` custom properties).
- Green as primary accent + red/orange reserved for severity is a deliberate
  system: color carries finding-severity meaning, it is not decoration.
- Contrast fix applied during rewrite: the code-comment color `#6c7682` failed
  WCAG AA on `--code-bg` (4.19:1). Replaced with `#7c8794` (5.3:1).

## Typography

- Body / UI: Inter, falling back to `system-ui, -apple-system, Segoe UI, Roboto, sans-serif`.
- Code / mono: JetBrains Mono, falling back to `ui-monospace, SFMono-Regular, Menlo, monospace`.
- Source: docs/index.html:18 (font declarations), :40 and :45 (font-family stacks).
- Inter/JetBrains Mono are the repo's existing typeface decision, so they stay
  named as the first choice. The rewrite drops the Google Fonts CDN link (the
  page must be self-contained with no external dependency), so the system
  fallbacks carry the page for visitors who do not have the fonts installed.

## Mood

Dark by default. This is a developer/terminal tool, which is the legitimate
reason R-21 allows for a fixed dark theme (not "dark looks tech"). The mood is
a working terminal at night: quiet ground, bright green for the operator's
attention, red/orange only where a real severity exists.

- Source: docs/index.html:12 `<meta name="theme-color" content="#0b0f14">` and the dark `:root` palette.

## Dial

`Dial: ENERGY 2 / RHYTHM 2 / MOTION 1` (derived, awaiting owner confirmation).

- ENERGY 2: the hero headline is large and confident (`clamp(40px, 6vw, 64px)`,
  docs/index.html:80) with a single green accent, but the page stays a tool
  reference rather than an agency showpiece. Balanced, Stripe/Vercel tier.
- RHYTHM 2: section compositions already vary (split hero, three-column feature
  grid, command cards, wide detector tables, a two-column finding/report view,
  an ASCII architecture diagram, callouts). Consistent system with real breaks.
- MOTION 1: the only motion in the source is hover transitions
  (docs/index.html:113-115). No scroll choreography. The owner wants an
  informative reference, so hover states plus a brief copy-confirmation are the
  ceiling. No perpetual loops.

## Constraints

- Single self-contained HTML file, inline CSS and JS, no CDN, no external
  dependencies (build requirement for this rewrite).
- The "Authorized use only" framing must stay prominent (docs/index.html:582-584).
- Attribution must stay: Apache-2.0 for ngehe, MIT for the embedded SecLists
  wordlists (README.md:366-368, internal/wordlist/NOTICE.md).
- Sample scan output is illustrative and must be labeled as such, not presented
  as a real capture.

## Open (questions for the owner, not guessed)

1. Version number. The previous page showed `v0.4`, but there is no git tag,
   no VERSION file, no version constant in the source, and no `--version` flag
   (verified: `git tag` empty; grep of cmd/ and internal/ found none). README
   only says "Status: alpha". The rewrite drops `v0.4` and keeps "alpha". Is
   there an intended release version to display, and should the CLI expose it?
2. Fonts. Should the site self-host Inter/JetBrains Mono woff2 files (to keep
   the exact typefaces without a CDN), or is the system-font fallback fine?
3. Companion tools. `cornela` and `milog` are linked as companion projects
   (README.md:347-352). Are those repos public and current, so the links are
   safe to keep on the landing page?
4. `yum` is a sixth package manager the installer detects (install.sh:48) but
   the page lists five (brew/apt/dnf/pacman/apk). Include yum, or is the
   shorter list intentional?
