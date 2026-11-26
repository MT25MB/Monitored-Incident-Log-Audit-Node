---
name: "MILAN: Monitored Incident & Log Audit Node"
description: "A local, guarded SOC triage agent documented as an incident record."
colors:
  paper: "#f4f3ee"
  surface: "#ffffff"
  ink: "#17201e"
  muted: "#52605c"
  line: "#d3d6cf"
  accent: "#a8432a"
  good: "#2f6a5c"
  code-bg: "#17201e"
  code-fg: "#e8ece7"
  inline-code-bg: "#e9e9e2"
typography:
  display:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "clamp(2.6rem, 5vw, 3.9rem)"
    fontWeight: 700
    lineHeight: 1.04
    letterSpacing: "-0.04em"
  headline:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "clamp(2rem, 3.4vw, 2.6rem)"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-0.03em"
  title:
    fontFamily: "Archivo, system-ui, sans-serif"
    fontSize: "1.15rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
    fontSize: "17px"
    lineHeight: 1.6
  label:
    fontFamily: 'ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace'
    fontSize: "14px"
    fontWeight: 600
    lineHeight: 1
spacing:
  xs: "12px"
  sm: "16px"
  md: "24px"
  lg: "48px"
  xl: "64px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    padding: "12px 18px"
  button-primary-hover:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.paper}"
  case-file:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    padding: "22px 24px 20px"
  table:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    padding: "11px 16px"
  code-block:
    backgroundColor: "{colors.code-bg}"
    textColor: "{colors.code-fg}"
    padding: "22px 24px"
---

# Design System: MILAN: Monitored Incident & Log Audit Node

## Overview

**Creative North Star: "The Incident Record"**

MILAN's documentation reads as a case file, not a product landing page. A warm paper ground, hairline ink-grey rules, and one white case card make the page behave like a reproducible report: a verdict, a short evidence list, and a containment gate paused for a person. Density is calm and forensic — generous vertical rhythm between ruled sections, tight monospaced data inside the card. The confirmed visual rejection is the eyebrow/numbered-list SaaS template; nothing in the build uses kickers, pills, decorative badges, or shadows.

Personality is plain and human. Colour is almost entirely ink on paper, with two restrained signals: brick red for the moments that need attention — a verdict, a pending action, a link, a focus ring — and a deep green reserved for measured benchmark figures. The self-hosted Archivo face carries every heading with tight negative tracking, the system sans carries prose, and a system mono carries identifiers, commands, and data cells. All assets are local and the system needs no build step, so it stays legible offline.

**Key Characteristics:**
- Warm paper ground (#f4f3ee) with a single white surface step and 1px hairline rules for all structure.
- Two signals: brick red for attention, deep green for benchmark results.
- Archivo display headings, system-sans body, system-mono for identifiers and data.
- A case-file signature: ruled case header, verdict, definition-list evidence, and a paused HITL gate with two pending actions.
- Flat and square: no shadows, no radius, no icon glyphs.
- One container (1120px), one responsive pair of breakpoints (900px, 560px), reduced-motion honored.

## Colors

The palette is a restrained paper-and-ink family: warm neutral grounds, one near-black ink, a mid grey for secondary text, light hairline rules, and two narrow signals — brick red for attention, deep green for results. There are no gradients or decorative fills.

### Primary
- **Warm Paper** (#f4f3ee, `paper`): The page ground; also the foreground on dark ink surfaces (the solid button, skip link, and text selection). Pinned by the brief as the deliberate system ground.
- **Brick Red** (#a8432a, `accent`): The attention signal — links, the "Malicious" verdict, "Pending" states, the caret, selection, focus outline, and button hover. Its scarcity is what makes it read as attention.

### Secondary
- **White Surface** (#ffffff, `surface`): The single raised step; the case card and every data table sit on white against the paper ground.
- **Signal Green** (#2f6a5c, `good`): The result signal — the final data cell of the `.metrics` benchmark table, where positive figures such as 100% and $0.00 land. It is a quieter counterpart to brick red and appears nowhere else.

### Neutral
- **Ink Charcoal** (#17201e, `ink`): Primary body text, brand wordmark, button fill, skip-link fill, and the code-block field — a near-black with a green cast, not pure black.
- **Muted Sage-Grey** (#52605c, `muted`): Secondary text — ledes, captions, table cells, metadata labels, and footer copy.
- **Hairline Grey** (#d3d6cf, `line`): Every border, divider, and rule, always 1px.
- **Code Field / Code Text** (#17201e / #e8ece7, `code-bg` / `code-fg`): The dark code block; the field shares the ink value and the text is an off-white tint.
- **Inline Code Field** (#e9e9e2, `inline-code-bg`): The light field behind inline code, with inherited ink text.

### Named Rules
**The Brick-Red-Is-Signal Rule.** Accent is never a field or decoration. It appears only on verdicts, pending states, links, focus, caret, selection, and hover — the moments asking for attention.

**The Green-Figures Rule.** Green figures are results. Green is used only for the result cells of the benchmark table; it never colours a verdict, a pending state, or decoration, so a green number always reads as a measured outcome.

**The Hairline Rule.** Every boundary is one pixel of `line`, never a shadow, gradient, or colour block.

## Typography

**Display Font:** Archivo (self-hosted woff2, fallback `system-ui, sans-serif`)
**Body Font:** system UI stack (`system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`)
**Label/Mono Font:** system monospace stack (`ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace`)

**Character:** Archivo is a compact grotesque with tight, confident headings; it is paired with a neutral system sans for reading and a plain system mono for machine-readable values. Roles never cross: headings are always Archivo, prose always the sans, identifiers and data always mono. No text is uppercased for tracking, and both heading levels use `text-wrap: balance` to keep their lines even.

### Hierarchy
- **Display** (Archivo, 700, `clamp(2.6rem, 5vw, 3.9rem)`, line-height 1.04, tracking −0.04em): the single H1, capped at 15ch.
- **Headline** (Archivo, 700, `clamp(2rem, 3.4vw, 2.6rem)`, line-height 1.12, tracking −0.03em): section H2s.
- **Title** (Archivo, 600, `1.15rem`, line-height 1.3, tracking −0.02em): the case-card title; section H3s use the body face at 600 `1.25rem`.
- **Body** (system sans, 400, `17px`, line-height 1.6; `16px` at ≤560px): prose, capped at 68ch in sections and 46ch for the lede.
- **Label** (system mono, 600, `12–14px`, line-height 1): case IDs and pending states; evidence values and data cells use the same mono at `13px`/`14px`, in normal case.

### Named Rules
**The Mono-for-Data Rule.** Mono is reserved for identifiers, commands, inline code, and data cells. Prose and headings never use it, and nothing is uppercased for tracking.

## Layout

One centred container governs all content: `width: min(calc(100% - 48px), 1120px)` — a 1120px maximum with a 24px gutter each side; at ≤560px the formula becomes `min(calc(100% - 32px), 1120px)` for a 16px inset. The hero is a two-column grid (copy and case card) of `minmax(0, 1fr)` and `minmax(380px, 0.92fr)` with a 64px gap, padded 72px above and 64px below. Body sections are single-column blocks separated by a 1px top rule and 64px vertical padding, with an optional two-column `.columns` grid at a 48px gap. Data tables sit inside a horizontal scroll wrapper with a 540px minimum width so narrow screens keep them readable.

The spacing rhythm is contextual but recurring: 64px between major sections, 48px for the container inset and column gaps, 24px in the header, 16px of horizontal table-cell padding, 12px of vertical cell padding, and 10–20px inside controls. The source defines no formal spacing scale — its only spacing custom property is defined but unused — so these are the values the components actually repeat, not a named scale.

Responsive: at ≤900px the hero and `.columns` collapse to one column (gaps of 40px and 22px; hero padding 56px/48px). At ≤560px body type drops to 16px, the container inset tightens to 16px, the header loses its minimum height, nav gap shrinks to 14px, sections pad to 44px, and evidence rows stack their label/value columns. `html` clips horizontal overflow and scrolls smoothly; `prefers-reduced-motion` disables smooth scroll and zeroes all transition and animation durations.

## Elevation & Depth

This system is flat. There are no box shadows anywhere in the build — depth is conveyed only by the paper-to-white tonal step (the case card and tables are white on paper) and by 1px hairline rules. The case card is raised by a surface change plus a border, never by a shadow.

### Named Rules
**The Flat-By-Default Rule.** Surfaces are flat at rest and in every state. Never introduce shadows, glows, or tonal layering beyond the single paper/white step; use a hairline rule to separate.

## Shapes

Everything is square. No radius appears in the build, so corners are unrounded throughout — buttons, the case card, tables, code blocks, and inline code chips all keep 90° corners. Form is carried by hairline borders (`1px solid line`) and ink-on-paper contrast rather than by corner treatment. Buttons and chips are plain rectangles; the case card is a bordered white rectangle with a ruled header and ruled definition rows. There are no pills, icon glyphs, or decorative shapes beyond the logo raster.

## Components

### Buttons
- **Shape:** Square corners, no radius.
- **Primary:** Ink fill (#17201e), paper text (#f4f3ee), `12px 18px` padding, 600 `14px/1` system sans.
- **Hover / Focus:** Hover flips the fill to brick red (#a8432a) and holds paper text; focus is a 2px accent outline with 3px offset (the global focus treatment).
- **Companion text link:** No fill, accent text at `14px`, underline-offset 3px with a bottom border on currentColor.

### Case File (signature component)
- The hero's right column: white surface, 1px `line` border, `22px 24px 20px` padding.
- **Head:** baseline-aligned flex — case ID in mono 600 `14px`, case-kind in muted `13px`, with a bottom rule.
- **Title:** Archivo 600 `1.15rem/1.3`, tracking −0.02em.
- **Verdict:** word in Archivo 700 `1.6rem` accent, detail in muted `13px`.
- **Evidence:** definition list; each row is a `118px`/`1fr` grid with a 10px gap and bottom rule, labels muted `13px`, values mono `13px/1.4`, long values wrapping.
- **Gate:** "Paused at containment gate" state line, ruled rows carrying "Pending" in mono 600 `12px` accent, and the muted `13px` note "Both proposals await a human decision before anything executes."

### Data Tables
- White surface, 1px `line` border, collapsed borders, `font-variant-numeric: tabular-nums`, `14px`, 540px minimum width, inside a horizontal scroll wrapper.
- Left-aligned muted `13px` caption with a bottom rule. Header cells 600 `13px/1.4` muted; row headers 600; body cells muted; the final cell of each row is mono for machine values. Row separators are bottom rules, removed on the last row.
- The final cell is ink on the trace and case tables, and signal green (`good`) on the `.metrics` benchmark table — the one place green appears.

### Code Block
- Dark `#17201e` field with light `#e8ece7` mono text at `14px/1.75`, `22px 24px` padding, `overflow-x: auto`, and 24px vertical margins. Inline code is the inverse: light `#e9e9e2` field, inherited ink text, `0.88em`, `1px 5px` padding.

### Navigation
- Compact header: flex, space-between, 24px gap, 76px minimum height, bottom rule. The brand is a 36px logo with a mono fallback and an Archivo 700 `18px` wordmark (tracking −0.02em). Links are muted `14px` with 6px vertical padding; hover turns accent; focus uses the global accent outline. At ≤560px the minimum height drops and gaps tighten.

## Do's and Don'ts

### Do:
- **Do** centre content in the 1120px container using `min(calc(100% - 48px), 1120px)`, tightening to a 16px inset at ≤560px.
- **Do** build structure from 1px `line` rules and the paper/white step, keeping both signal tokens (`accent`, `good`) on signal only.
- **Do** set display headings in Archivo with negative tracking and balanced lines, prose in the system sans, and identifiers/data in mono.
- **Do** colour only the result cells of the benchmark table green, and keep every other table's final cell ink.
- **Do** keep surfaces flat and square, and render numeric values in tabular figures.
- **Do** honor `prefers-reduced-motion` and keep the page navigable without JavaScript.

### Don't:
- **Don't** add border-radius, pills, shadows, glows, or gradient fills.
- **Don't** use brick red as a large field or background; it is a signal colour, not a ground.
- **Don't** apply green outside benchmark result cells — it is not a general success or accent colour.
- **Don't** set body copy in mono or set display headings in a system font.
- **Don't** fill case-file or table cells with placeholder values; displayed records must stay checkable.
