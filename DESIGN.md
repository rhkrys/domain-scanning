# Design guide: techinpeace.com / Secure & Grow / Cyber Protection

The visual system used by the landing page, the privacy and Terms page, the domain scanner, the report email, and the Gumroad profile page. It is the Cyber Protection (CPI) brand: navy and gold, condensed capital headings, sharp corners.

Source of truth in code: `landing/index.html` (`:root` and `<style>`), `landing/privacy.html`, `public/styles.css` (scanner), `src/email/render.js` (email), `gumroad/profile.html`.

## Brand

- **Names:** Secure & Grow (the offer), Cyber Protection Consulting (the brand), Chlamys Piste Inc. (the legal entity in the policies).
- **Feel:** trustworthy and precise, not playful. Light pages, deep navy bars, gold used sparingly as the accent.
- **Logo:** gold woven sphere, `public/logo-gold.png` (1300 x 1315 px, transparent PNG). Sits on navy. Wordmark beside it in text: "SECURE & GROW" or "CYBER PROTECTION", with a small gold "CONSULTING SERVICES" descriptor.

## Color

| Token | Hex | Use |
|---|---|---|
| Deep navy | `#142534` | Header, footer, hero, headings |
| Darkest navy | `#101f36` | Hero gradient start, footer |
| Primary navy | `#203a7b` | Buttons, links, eyebrow text, stripe accent |
| Mid navy | `#1b3060` | Hero gradient end |
| Pale navy | `#e8eff7` | Text on dark backgrounds, icon tiles |
| Gold | `#e8ae5c` | Rules, borders, header/footer line, primary button, logo |
| Deep gold | `#b9822a` | Gold text on light backgrounds, gold button end |
| Soft gold | `#f0c889` | Gold text on dark backgrounds |
| Cream | `#faf3dd` | Callouts, check badges, scanner strip |
| Paper | `#f1f8fa` | Alternate section backgrounds |
| White | `#ffffff` | Cards and main sections |
| Ink | `#0d1a26` | Body text |
| Muted | `#6a7886` | Secondary text |
| Border | `#d9dee4` | Card, table and input borders |

### Status colors (scanner and forms only)

| Token | Hex | Meaning |
|---|---|---|
| Pass | `#1f7a5a` | Check passed, grades A and B |
| Review | `#c98a2b` | Worth a look, grades C and D |
| Fail | `#c0392b` | Needs fixing, grades E and F, form errors |
| Info | `#6a7886` | Neutral information |

### Gradients

- **Hero:** `linear-gradient(160deg, #101f36, #142534 55%, #1b3060)` with a soft gold glow: `radial-gradient(1200px 500px at 80% -10%, rgba(232,174,92,.16), transparent 60%)`.
- **Gold button:** `linear-gradient(135deg, #e8ae5c, #b9822a)` with dark navy text.

### Dark mode

The website itself is **light only**. The Gumroad profile page follows the visitor's system setting; its dark values are background `#0c1727`, surface `#132135`, text `#eaf1f8`, muted `#9fb0c2`, border `#26364c`, header `#0a1524`, accent `#e8ae5c`, gold text `#f0c889`.

## Typography

| Role | Font | Notes |
|---|---|---|
| Headings, prices, buttons, grade | **League Gothic** (fallbacks Oswald, Bebas Neue, Arial Narrow) | Weight 400, uppercase, tight leading (about 1.0) |
| Body and UI | **Lato** (fallbacks Helvetica Neue, Arial) | Regular 400 for body, Bold 700 for emphasis and small nav links |
| Monospace | JetBrains Mono | Scanner input placeholders only |

- **Lato has no 600 or 800 weight.** Use 400 or 700 only. Load: `family=Lato:wght@400;700`.
- Hero heading: `clamp(40px, 6vw, 68px)`, uppercase. Section headings: `clamp(30px, 4vw, 44px)`, uppercase. Card headings 24 to 26 px. Prices 46 to 48 px.
- Eyebrow (small label above a heading): 13 px, Bold, uppercase, letter-spacing `.16em`, primary navy (soft gold on dark), with a 2 px gold underline.
- Body copy 15.5 to 17.5 px; small notes 13 to 14.5 px. Line height 1.6.
- Google Fonts link used on every page: `League Gothic`, `Oswald` (400, 600), `Lato` (400, 700).

## Shape, spacing, layout

- **Corners:** 2 px everywhere (`--radius: 2px`). Only small badges and the "Most Popular" tag are pill shaped.
- **Shadow:** `0 10px 30px rgba(20,37,52,.12)` on hover cards and the featured plan.
- **Page width:** 1100 px (landing), 860 px (privacy and Terms), 760 px (scanner form and results), 1040 px (scanner top bar). Side padding 24 px (20 px in the scanner).
- **Section spacing:** about 74 to 84 px top and bottom on the landing page.
- **Breakpoints:** 860 px is the main one (grids collapse to one column, navigation links hide). Also 900 px (pricing grid), 780, 760 and 640 px (scanner and Gumroad nav), 560 px (scanner corner stripe hides).

## Signature elements

- **Gold rule:** a 2 px gold line under eyebrows, on the header and footer edges, and above key cards (3 px gold top border).
- **Diagonal stripe corner:** a 45 degree navy and gold stripe triangle in the top-right of the hero (72 px on the landing page, 64 px in the scanner). Landing stripes are 6 px navy then 6 px gold; the scanner's are 5 px each.
- **Grade badge (scanner):** a square with the top-left and bottom-right corners cut off 12 px, filled with the status color, League Gothic letter inside.
- **Dark bars:** header and footer are deep navy with a 2 px gold line (bottom of header, top of footer).

## Components

- **Buttons:** League Gothic, uppercase, 18 px, letter-spacing `.04em`, padding 13 x 26 px, 2 px corners. Lift 2 px on hover.
  - *Gold* (primary action): gold gradient, dark navy text.
  - *Navy* (secondary): `#203a7b` fill, white text.
  - *Outline* (on dark backgrounds): 2 px gold border, white text.
- **Header:** sticky, deep navy, logo and wordmark on the left, links on the right, one outline button ("Check My Domain") and one gold button ("Join the Waitlist"). Links hide below 860 px; buttons stay.
- **Persona and plan cards:** white, 1 px border, 3 px gold top border. The featured plan has a 2 px gold border, a shadow and a "Most Popular" gold pill.
- **Feature lists:** round cream check badges with a gold check mark.
- **FAQ:** native `<details>` items with a `+` / `-` marker in gold.
- **Testimonials:** white cards with a gold top border, a large gold quotation mark, and the name in bold with the role in small uppercase grey.
- **Forms (scanner):** uppercase small labels, 1 px borders, sharp corners, navy focus ring. Errors in the fail red, bold, 14 px. The consent checkbox label is normal case with underlined navy links.
- **Callouts:** cream background with a 3 px gold left border.
- **Tables (privacy and Terms):** thin borders, pale header row with small uppercase bold labels.

## Imagery

- Logo on dark navy only. Do not place it on white.
- Header banner for the Google Form: `forms/form-header.png`, 1600 x 400 px, navy gradient, logo, "SECURE & GROW", gold rule, stripe corner.
- No stock photography is used. Emoji are used sparingly as icons on cards.

## Email

`src/email/render.js` reuses the same palette with inline styles (email clients ignore most external CSS). Body font is Lato with Arial as the fallback, since many mail apps will not load web fonts.

## Do and don't

- **Do** keep gold to accents: rules, buttons, key numbers. Use deep gold (`#b9822a`) for gold text on light backgrounds and soft gold (`#f0c889`) on dark.
- **Do** keep corners at 2 px and headings in League Gothic capitals.
- **Do** use status colors only for real status (pass, review, fail).
- **Don't** use Lato weights 600 or 800.
- **Don't** put light gold text on white or muted grey on navy for important content.
- **Don't** add rounded, soft, or gradient-heavy styles. The look is flat, sharp and high contrast.

## Not verified

Color contrast ratios have not been measured against WCAG. Check them before making any accessibility claim.
