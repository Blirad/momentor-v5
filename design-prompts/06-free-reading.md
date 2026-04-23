# 06 — Free Reading (Prologue) Prompt (Variant AI)

## Prompt

```
Design the Free Reading screen (called "Prologue") for Momentor. This is the complimentary analysis that every user receives — it must deliver real value while clearly signaling that a deeper, premium analysis exists.

DELIVER TWO FRAMES:
- Frame 1: PC (1440×900, scrollable — show ~1400px of content)
- Frame 2: Mobile (390×844, scrollable — show ~1600px of content)

GLOBAL STYLE: Follow established style board.

---

CONTENT STRUCTURE:

The Free Reading has 2 chapters. Each chapter is a full-width section with editorial-style content.

```
[Sticky Header]
─────────────────────
[Chapter Navigation — Side dots (PC) / Bottom bar (Mobile)]

═══════════════════════════════════════════
CHAPTER I — "WHO YOU ARE"
═══════════════════════════════════════════

[Section Header]
  Chapter label (sans 500, 13px, gold-dim, uppercase):
  "CHAPTER I"
  Chapter title (serif 400, 32px, white):
  "Who You Are"
  Divider: thin gold line, 40px

─────────────────────
[Pattern Profile Block]

  Left (or top on mobile): Daymaster abstract symbol (64×64)
  Right (or below on mobile):
    Pattern name (serif 500, 22px, gold): "The Architect"
    Element type (sans 500, 13px, text-muted): "STRUCTURED WOOD"
    
  Below:
  Origin narrative (serif 400, 17px, text-primary, line-height 1.8):
  "You carry the energy of deep-rooted timber — the kind that
   grows slowly, plans structurally, and holds weight others
   cannot. Your mind maps systems before it names emotions..."
  (3-4 paragraphs of rich, insightful personality narrative)

─────────────────────
[Identity Tags — Horizontal scroll on mobile]

  5-6 trait pills in a row:
  [ Methodical ] [ Long-term thinker ] [ Quietly ambitious ] 
  [ Structured ] [ Foundation-builder ] [ Pattern-aware ]
  
  Style: gold-tint bg, gold-dim text, 8px radius, 14px

─────────────────────
[Shadow Section — Callout Block]

  Left gold border (2px, gold), gold-tint background
  
  Label (sans 500, 13px, gold, uppercase): "THE OTHER SIDE"
  
  Text (serif 400 italic, 16px, text-secondary, line-height 1.7):
  "Your strength becomes a trap when you mistake rigidity for
   reliability. The same precision that builds empires can
   calcify into control..."
  (1-2 paragraphs)

─────────────────────
[Invitation — Pull Quote]

  Large serif text (serif 300, 22px, gold-soft, center, italic):
  "What would you create if you trusted the foundation
   was already solid enough?"

═══════════════════════════════════════════
CHAPTER II — "LIFE PHASES"
═══════════════════════════════════════════

[Section Header]
  "CHAPTER II"
  "Your Life Phases"

─────────────────────
[Phase Explainer — Brief]

  (sans 400, 15px, text-secondary):
  "Your pattern shifts in 10-year cycles. Each phase carries
   a distinct energy signature that shapes your priorities,
   challenges, and opportunities."

─────────────────────
[Timeline — Horizontal on PC, Vertical on Mobile]

  PC: Horizontal timeline with cards
  Mobile: Vertical stack of cards

  Each Phase Card:
  ┌─────────────────────────────┐
  │ Age Range (sans 600, 14px): │
  │ "Age 25-35"                 │
  │                             │
  │ Period (sans 400, 13px,     │
  │  text-muted): "2018-2028"   │
  │                             │
  │ Phase Name (serif 500,      │
  │  18px, white):              │
  │ "Expansion Phase"           │
  │                             │
  │ Description (sans 400,      │
  │  14px, text-secondary):     │
  │ "A period of outward        │
  │  growth and visibility..."  │
  │                             │
  │ [Element indicator: thin    │
  │  colored line at top of     │
  │  card matching phase        │
  │  element]                   │
  └─────────────────────────────┘

  Current phase card: 
  - Gold border instead of standard border
  - "NOW" badge (gold pill, top-right)
  - Slightly elevated (surface-1 background)

  Past phases: 60% opacity
  Future phases: standard opacity but no detail text (teaser)

  Show 3-5 phase cards depending on birth year.

─────────────────────
[Phase Insight — Current Phase Detail]

  For the current phase only, show expanded narrative:
  
  (serif 400, 17px, text-primary, line-height 1.8):
  "You are in the middle of a Fire-driven expansion cycle.
   The energy around you favors bold moves, public presence,
   and creative output..."
  (2-3 paragraphs)

═══════════════════════════════════════════
[END OF FREE CONTENT — UPGRADE TEASER]
═══════════════════════════════════════════

[Blurred Preview Section]

  Behind a gaussian blur (12px) + dark overlay (60%):
  Show a glimpse of Chapter III content (2026 Forecast)
  — Monthly grid cards, partially visible
  — Life domain accordion headers
  
  Overlay text (centered):
  
  Section label (sans 500, 13px, gold, uppercase):
  "CHAPTER III — YOUR 2026 FORECAST"
  
  Headline (serif 400, 28px, white):
  "See what this year holds."
  
  Subtext (sans 400, 15px, text-secondary):
  "10 life domains. Monthly insights. Personalized guidance."
  
  [CTA: "Unlock Full Reading — $15.99"]
  Gold button, 52px, max-width 320px
  
  Fine print (sans 400, 12px, text-muted):
  "One-time payment. Yours to keep forever."
```

---

PC LAYOUT SPECIFICS:
- Max content width: 680px, centered
- Chapter nav dots on left side (fixed, vertical)
  - 4 dots, top 2 gold (active/available), bottom 2 dim (locked)
  - Current chapter dot: larger, filled gold
- Timeline: horizontal scroll with snap points
- Pattern profile: 2-column (symbol left, text right)
- Generous margins: 64px between major sections

MOBILE LAYOUT SPECIFICS:
- Full-width, 20px padding
- Bottom navigation: 4 chapter buttons
  - "I" and "II" active, "III" and "IV" show lock icon
  - Current: gold underline
- Timeline: vertical card stack
- Pattern profile: stacked (symbol → name → text)
- Sticky bottom bar appears after scrolling past Chapter I:
  "Unlock Full Reading — $15.99" (slim bar, 48px, gold)

DESIGN PRINCIPLES FOR FREE CONTENT:
1. It must feel COMPLETE — not like a teaser that got cut off
2. The quality of writing and presentation should match paid content
3. The free/paid boundary should feel like "Chapter I-II / Chapter III-IV" not "free crumbs / real content"
4. The blurred preview at the end creates aspiration without frustration
5. NO: "Sign up to see more" / "Limited preview" / aggressive upsell language

VISUAL RHYTHM:
- Chapter headers create clear section breaks
- Alternate between full-width text and contained cards
- Use the gold callout block sparingly (once per chapter max)
- Whitespace between sections: minimum 48px

FORMAT:
- Frame 1: 1440×1400 (PC, scrollable)
- Frame 2: 390×1600 (Mobile, scrollable)
```
