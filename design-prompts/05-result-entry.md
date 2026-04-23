# 05 — Result Entry Prompt (Variant AI)

## Prompt

```
Design the Result Entry sequence for Momentor: the loading transition and the initial result summary screen. This is the moment between form submission and the reading — it must feel like a precision instrument processing data.

DELIVER TWO FRAMES:
- Frame 1: Loading State (PC 1440×900)
- Frame 2: Result Summary / Entry (Mobile 390×844, scrollable — show first ~1200px)

GLOBAL STYLE: Follow established style board.

---

FRAME 1: LOADING STATE (PC)

Full-screen overlay on #0d0b1e background.

CENTER ELEMENT — ORBITAL ANIMATION:
- The signature orbital diagram from the Hero, but in motion
- Rings rotating at different speeds (suggest this with motion blur / offset)
- Central point pulsing with gold glow
- Element-color orbital lines actively tracing paths
- Size: ~400×400px centered
- Feels like: a precision instrument calibrating, not a loading spinner

PROGRESS INDICATORS (below orbital):
- Current status text, cycling through:
  1. "Mapping birth patterns..."
  2. "Analyzing elemental composition..."
  3. "Calculating phase cycles..."
  4. "Generating your profile..."
- Text: Inter 400, 15px, text-secondary, center
- Subtle fade transition between each (800ms per step)

PROGRESS BAR (optional, subtle):
- Thin line (2px), full width max 320px
- Gold fill animating left to right
- Below status text, 16px gap

NO:
- Percentage numbers
- Spinning circles or generic loaders
- Any text revealing the Eastern system behind the calculation
- Terms like "four pillars," "heavenly stems," "saju," "bazi"

TIMING NOTE:
This screen shows for ~4-5 seconds. It should feel substantive, not rushed.

---

FRAME 2: RESULT SUMMARY / ENTRY (Mobile, scrollable)

This is the first screen after loading completes. It introduces the user's pattern profile before they dive into detailed chapters.

LAYOUT (top to bottom):

```
[Header: ✦ Momentor]
─────────────────────
[Pattern Identity Card]

  Center-aligned:
  
  Daymaster Symbol (abstract glyph, ~80×80px)
  — NOT a Chinese character
  — An abstract geometric symbol representing the pattern type
  — Uses the element color of this type (e.g., green for Wood)
  — Thin-line, elegant, unique per type
  
  Pattern Name (serif 500, 24px, gold):
  "The Architect"
  
  Pattern Code (sans 500, 13px, text-muted, uppercase):
  "PATTERN TYPE: STRUCTURED WOOD"
  
  Divider (thin gold line, 40px wide, centered)
  
  Hook Line (serif 300 italic, 18px, text-primary):
  "You build worlds with quiet precision —
   and rarely show the blueprints."
  
─────────────────────
[3 Keyword Pills — horizontal row]
  
  [ ◆ Strategic ]  [ ◆ Resilient ]  [ ◆ Reserved ]
  
  Gold-tint bg, gold-dim text, 8px radius, 13px uppercase
  ◆ is a small element-color dot before each word

─────────────────────
[Element Composition — Minimal Bar]
  
  Section label (sans 500, 13px, text-muted, uppercase):
  "ELEMENT COMPOSITION"
  
  Horizontal stacked bar (full width, 8px height, rounded):
  — 5 segments in element colors, proportional to composition
  — e.g., 35% Wood (green), 25% Fire (red), 15% Earth (amber), 15% Metal (silver), 10% Water (blue)
  
  Legend below: 5 items in a row
  "● Wood 35%  ● Fire 25%  ● Earth 15%  ● Metal 15%  ● Water 10%"
  (sans 400, 13px, each with its element color dot)

─────────────────────
[Chapter Navigation Preview]

  Section label: "YOUR ANALYSIS"
  
  3 chapter cards, stacked vertically, 12px gap:
  
  Card 1 (tappable):
  "Chapter I — Who You Are"         [→]
  "Your core pattern and traits"
  FREE badge (green pill)
  
  Card 2 (tappable):
  "Chapter II — Life Phases"        [→]
  "Your 10-year energy cycles"
  FREE badge
  
  Card 3 (locked appearance):
  "Chapter III — 2026 Forecast"     [🔒]
  "This year decoded, month by month"
  FULL READING badge (gold pill)
  
  Card 4 (locked appearance):
  "Chapter IV — Today's Energy"     [🔒]
  "Your pattern for right now"
  FULL READING badge (gold pill)

─────────────────────
[CTA: "Start Reading — Free" button]
  Full-width gold, 52px
  Below: "Full analysis available for $15.99"
  (sans 400, 13px, text-muted)
```

CARD STYLES (chapter navigation):
- Free chapters: surface-2 fill, border, normal opacity
- Locked chapters: surface-2 fill, slightly dimmer (80% opacity), lock icon instead of arrow
- Badge styles:
  - FREE: #4ade80 text, rgba(74,222,128,0.1) bg, 4px radius
  - FULL READING: gold text, gold-tint bg, 4px radius

PATTERN IDENTITY CARD:
- This replaces the old "Day Master" card
- The abstract symbol is NOT a Chinese character — it's a geometric glyph
  (think: a stylized tree for Wood, a crystal structure for Metal, a wave for Water, a flame geometry for Fire, a layered form for Earth)
- The symbol should feel like a logo mark, not a pictogram
- Background: subtle radial glow in the element color at ~5% opacity behind the symbol

MOBILE SPECIFICS:
- 20px horizontal padding throughout
- Cards are full-width
- Smooth scroll, no pagination
- Sticky header on scroll

TRANSITION FROM LOADING:
- The orbital animation contracts to the center, morphs into the daymaster symbol
- Fade-up reveal of the Pattern Identity Card
- Staggered fade-up for keyword pills, composition bar, chapter cards

FORMAT: 
- Frame 1: 1440×900 (loading, PC)
- Frame 2: 390×1200 (result entry, Mobile, scrollable)
```
