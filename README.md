# tpaidakis.com — Personal Security Blog

Static site built with [Hugo](https://gohugo.io), deployed to [GitHub Pages](https://pages.github.com) at **tpaidakis.com** via Cloudflare.

---

## Table of Contents

- [Tech Stack](#tech-stack)
- [Local Development](#local-development)
- [Writing a Post](#writing-a-post)
  - [Front Matter Reference](#front-matter-reference)
  - [CVE Writeup](#cve-writeup)
  - [Generic Writeup](#generic-writeup)
  - [Featured / Starred Post](#featured--starred-post)
  - [PoC Download Block](#poc-download-block)
- [Publishing](#publishing)
- [Site Structure](#site-structure)
- [Customization](#customization)
  - [About Page](#about-page)
  - [PGP Key](#pgp-key)
  - [Disclosure Policy](#disclosure-policy)
  - [Navigation](#navigation)
  - [Colors and Fonts](#colors-and-fonts)
- [Deployment](#deployment)

---

## Tech Stack

| Layer | Tool |
|---|---|
| Generator | Hugo v0.163.2 extended |
| Hosting | GitHub Pages (`theopaid/theopaid.github.io`) |
| Domain | tpaidakis.com via Cloudflare |
| CI/CD | GitHub Actions (`.github/workflows/deploy.yml`) |
| Syntax highlighting | Chroma (built into Hugo) |
| CSS | Custom, no frameworks |

---

## Local Development

Hugo must be installed (one-time setup):

```bash
brew install hugo
```

Start the local dev server from the project root:

```bash
hugo server --buildDrafts
```

The site is live at **http://localhost:1313**. It hot-reloads on every file save. The `--buildDrafts` flag makes draft posts visible locally so you can preview before publishing.

Stop the server with `Ctrl+C`. You do not need it running at any other time.

---

## Writing a Post

All posts live in `content/writeups/`. Each post is a single `.md` file.

### Front Matter Reference

Every post starts with a front matter block between `---` lines. Here is the full list of supported fields:

```markdown
---
title: "Your Post Title"
date: 2026-01-15
draft: false
summary: "One sentence shown on listing pages."
featured: false
cve: ""
tags: []
poc_url: ""
poc_sha256: ""
poc_notes: ""
---
```

| Field | Required | Description |
|---|---|---|
| `title` | Yes | Post title |
| `date` | Yes | Publication date (`YYYY-MM-DD`) |
| `draft` | Yes | `true` = hidden from production, visible locally with `--buildDrafts`. Set to `false` to publish. |
| `summary` | No | Short description shown on listing pages and in social previews |
| `featured` | No | `true` pins the post to a Featured section on the home page with a ★ |
| `cve` | No | CVE ID (e.g. `CVE-2024-1234`). Renders as a badge. Leave empty for non-CVE posts. |
| `tags` | No | List of tags for filtering (e.g. `["web", "rce", "critical"]`) |
| `poc_url` | No | URL to the PoC file. Renders a download block under the post header. Leave empty to hide. |
| `poc_sha256` | No | SHA-256 hash of the PoC file. Only shown if `poc_url` is set. |
| `poc_notes` | No | Short usage note shown in the PoC block. |

Fields left empty or omitted entirely do not render anything — the site handles both CVE writeups and generic posts with the same template.

---

### CVE Writeup

Create the file:

```bash
hugo new writeups/cve-2024-1234.md
```

This generates the file from the archetype at `archetypes/writeups.md` with the correct structure and all front matter fields pre-filled. Open it in any editor, fill in the fields, write the post, then set `draft: false` when ready.

Alternatively copy an existing post and edit it directly.

A typical CVE post front matter:

```markdown
---
title: "Auth Bypass in ExampleApp via JWT Algorithm Confusion"
date: 2026-03-15
draft: false
summary: "A critical authentication bypass allowing token forgery in ExampleApp ≤ 4.2.1."
cve: "CVE-2024-1234"
tags: ["web", "authentication", "critical"]
poc_url: "https://github.com/theopaid/pocs/raw/main/cve-2024-1234.py"
poc_sha256: "abc123..."
poc_notes: "Requires Python 3.10+. Run against a target with a known public key."
---
```

---

### Generic Writeup

For posts not tied to a CVE, omit or leave empty the CVE and PoC fields:

```markdown
---
title: "Initial Recon Methodology for External Assessments"
date: 2026-04-01
draft: false
summary: "How I approach external attack surface enumeration."
tags: ["recon", "methodology"]
---
```

No badge, no PoC block — just the post.

---

### Featured / Starred Post

Set `featured: true` on any post to pin it to a dedicated "Featured" section at the top of the home page. The post also gets a ★ prefix in all listing views.

Use this sparingly for landmark research — first exploitation of a vulnerability class, high-impact CVEs, etc.

```markdown
featured: true
```

---

### PoC Download Block

If a post has `poc_url` set, a styled block appears below the post header with a download link, the SHA-256 hash, and an optional usage note. The block does not appear if `poc_url` is empty.

```markdown
poc_url: "https://example.com/poc.py"
poc_sha256: "e3b0c44298fc1c149afb..."
poc_notes: "Run with Python 3.10+. Adjust HOST variable on line 12."
```

---

### Table of Contents

Generated automatically from `##` and `###` headings in the post body. No configuration needed. If a post has no headings, the ToC does not render.

---

## Publishing

Once the post is written and `draft: false`:

```bash
git add content/writeups/your-post.md
git commit -m "Add writeup: your title"
git push
```

GitHub Actions picks up the push, builds with Hugo, and deploys to GitHub Pages. The post is live on tpaidakis.com within ~60 seconds.

To unpublish a post, set `draft: true` and push again.

---

## Site Structure

```
.
├── archetypes/
│   └── writeups.md          # Template for new posts (hugo new uses this)
├── assets/
│   └── css/
│       └── main.css          # All site CSS — edit here for style changes
├── content/
│   ├── about.md              # About page content
│   ├── disclosure.md         # Vulnerability disclosure policy
│   └── writeups/             # All blog posts go here
├── layouts/
│   ├── _default/
│   │   ├── baseof.html       # Base template (header, footer, theme toggle)
│   │   ├── list.html         # Writeups listing page
│   │   ├── single.html       # Individual post page
│   │   └── terms.html        # Tags index page
│   ├── about/
│   │   └── single.html       # About page layout
│   └── index.html            # Home page
├── static/
│   ├── css/
│   │   ├── syntax-dark.css   # Chroma code highlighting (dark theme)
│   │   └── syntax-light.css  # Chroma code highlighting (light theme)
│   ├── CNAME                 # Custom domain for GitHub Pages
│   └── .nojekyll             # Tells GitHub Pages not to use Jekyll
├── .github/
│   └── workflows/
│       └── deploy.yml        # GitHub Actions — builds and deploys on push to main
└── hugo.toml                 # Site configuration
```

---

## Customization

### About Page

Edit `content/about.md` directly. The bio text is plain markdown at the top of the file. Below it are the Certifications section (raw HTML blocks for the badge grid) and the Contact section (PGP block). Edit only the prose — leave the HTML blocks intact unless you are adding or removing a cert.

### PGP Key

In `content/about.md`, find the PGP block and replace the placeholder fingerprint:

```html
<div class="pgp-block">
  <span class="pgp-label">PGP Public Key</span>
  <div class="pgp-body">
    <code class="pgp-fingerprint">YOUR FINGERPRINT HERE</code>
    <div class="pgp-links">
      <a href="https://keys.openpgp.org/search?q=your@email.com" rel="noopener">keys.openpgp.org</a>
    </div>
    <p class="pgp-note">Prefer encrypted communication for vulnerability reports and sensitive topics.</p>
  </div>
</div>
```

Update the `href` on the `keys.openpgp.org` link to point to your actual key search URL.

### Disclosure Policy

Edit `content/disclosure.md`. The 90-day timeline and other terms are yours to adjust. The page is linked in the main navigation automatically.

### Navigation

Menu items are defined in `hugo.toml`:

```toml
[[menu.main]]
  name = "Writeups"
  url = "/writeups/"
  weight = 1

[[menu.main]]
  name = "About"
  url = "/about/"
  weight = 2

[[menu.main]]
  name = "Disclosure"
  url = "/disclosure/"
  weight = 3
```

Add, remove, or reorder by editing `name`, `url`, and `weight` (lower weight = further left).

### Colors and Fonts

All visual tokens are CSS variables at the top of `assets/css/main.css`:

```css
:root {                          /* dark theme */
  --bg:         #0f0f0f;
  --bg-subtle:  #1a1a1a;
  --border:     #2a2a2a;
  --text:       #d4d4d4;
  --text-muted: #6b6b6b;
  --accent:     #5b8dd9;         /* links, interactive elements */
  --cve:        #c97b3e;         /* CVE badge and PoC block */
  ...
}

[data-theme="light"] {           /* light theme overrides */
  --bg:         #f8f8f6;
  ...
}
```

Change any value here to affect the whole site. The light theme block only needs to override values that differ from the dark theme.

Syntax highlight styles are separate files in `static/css/` — regenerate them with:

```bash
hugo gen chromastyles --style=monokai > static/css/syntax-dark.css
hugo gen chromastyles --style=tango  > static/css/syntax-light.css
```

Replace `monokai` / `tango` with any [Chroma style name](https://xyproto.github.io/splash/docs/).

---

## Deployment

Deployment is fully automated via `.github/workflows/deploy.yml`. Every push to `main` triggers a build and deploy. No manual steps needed after the initial setup below.

**One-time GitHub setup** (already done — documented here for reference):

1. Repo Settings → Pages → Source: set to **GitHub Actions** (not branch deploy)
2. DNS: four A records pointing to GitHub Pages IPs, managed via Cloudflare
3. `static/CNAME` contains `tpaidakis.com` — GitHub Pages reads this for the custom domain

**Hugo version** is pinned to `0.163.2` in `deploy.yml`. If you upgrade Hugo locally (`brew upgrade hugo`), update the version in `deploy.yml` to match or builds will diverge.
