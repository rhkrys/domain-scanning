# Gumroad handoff — @crystalpugh profile page + waitlist

Paste this into the chat that has Gumroad access, and attach `gumroad/profile.html`.

## The page to publish
- File: **`gumroad/profile.html`** (repo `rhkrys/domain-scanning`, branch `claude/sweet-goldberg-xqoyfg`) — or the attached copy.
- It's a custom **Secure & Grow** profile page: responsive, light + dark mode, links out to product pages (no checkout elements), and an email signup using `<form data-gumroad-follow>` with a `data-gumroad-follow-message` confirmation element.

## Tasks for the Gumroad chat
1. **Publish it** (replaces the entire @crystalpugh profile):
   `gumroad pages preview`  → review → `gumroad pages push profile`
   (or paste the HTML into Gumroad's page editor).
2. **Custom domain `store.techinpeace.com`:**
   - Gumroad → Settings → Custom domain → `store.techinpeace.com`.
   - DNS (GoDaddy): `CNAME  store → domains.gumroad.com` (use the exact target Gumroad shows if different).
3. **Replace product placeholders** in the page: `PRODUCT-SLUG-1`, `-2`, `-3` → real product URLs (`https://store.techinpeace.com/l/<slug>`).
4. **Follow form:** Gumroad auto-wires `data-gumroad-follow` to the email audience once the account is reviewed/compliant; until then it routes visitors to the subscribe page. Confirm compliance status.

## Send these two things BACK to the techinpeace chat
- **Gumroad seller ID** — from Settings → Follow-form embed (the hidden `seller_id` value), or view-source your profile for `seller_id`. Needed to wire the techinpeace.com landing waitlist (currently placeholder `YOUR_GUMROAD_SELLER_ID`).
- **Real product slugs / URLs** — to finalize the links on the profile page.

## Design reference (so the page stays on-brand if regenerated)
- Palette: navy `#142534` / `#203a7b`, gold `#e8ae5c` / `#b9822a`, paper `#f1f8fa`, ink `#0d1a26`.
- Fonts: **League Gothic** (display, uppercase headings), **Open Sans** (body).
- Logo: `https://www.techinpeace.com/logo-gold.png`
- Brand: "Secure & Grow" by Crystal Pugh / Cyber Protection Consulting.
- Must-haves: fully responsive, light + dark mode, product-page links only (no checkout embeds), `data-gumroad-follow` signup.
