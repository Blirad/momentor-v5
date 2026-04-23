# 09 — My Readings Prompt (Variant AI)

## Prompt

```
Design the "My Readings" screen for Momentor — a personal library where users access their saved analyses. This is a utility screen that should feel organized and premium.

DELIVER TWO FRAMES:
- Frame 1: PC (1440×900) — with 2-3 sample readings
- Frame 2: Mobile (390×844) — with 2-3 sample readings

GLOBAL STYLE: Follow established style board.

---

CONTEXT:
"My Readings" is accessible from the header navigation. It shows all readings the user has generated — both free Prologues and paid Full Readings. Users can also start new readings from here.

---

LAYOUT:

```
[Header: ✦ Momentor          + New Reading]
─────────────────────

[Page Title — left-aligned on PC, center on mobile]
  "My Readings" (serif 400, 32px, white)
  "Your saved analyses" (sans 400, 15px, text-secondary)

─────────────────────
[Reading Cards — vertical list]

CARD 1 (Full Reading — purchased):
┌─────────────────────────────────────────────┐
│                                             │
│  [Symbol: 48×48]   "Alex's Reading"         │
│   (element color)   Pattern: The Architect  │
│                     Wood · Born Mar 15 1992  │
│                                             │
│  ┌──────┐ ┌──────┐ ┌──────────────────┐    │
│  │ FULL │ │ 2026 │ │ Last opened:     │    │
│  │READING│ │      │ │ 2 days ago       │    │
│  └──────┘ └──────┘ └──────────────────┘    │
│                                             │
│  [Continue Reading →]                       │
│                                             │
└─────────────────────────────────────────────┘

CARD 2 (Prologue only — free):
┌─────────────────────────────────────────────┐
│                                             │
│  [Symbol: 48×48]   "Jordan's Reading"       │
│   (element color)   Pattern: The Catalyst   │
│                     Fire · Born Jul 8 1995   │
│                                             │
│  ┌────────┐ ┌──────────────────────────┐    │
│  │PROLOGUE│ │ Created: Jan 14, 2026    │    │
│  └────────┘ └──────────────────────────┘    │
│                                             │
│  [View Prologue]  [Upgrade to Full — $15.99]│
│                                             │
└─────────────────────────────────────────────┘

CARD 3 (Compatibility Reading):
┌─────────────────────────────────────────────┐
│                                             │
│  [Symbol] ⟷ [Symbol]  "Alex & Jordan"      │
│  (green)    (red)       Compatibility       │
│                         Reading             │
│                                             │
│  ┌─────────────┐ ┌────────────────────┐     │
│  │COMPATIBILITY│ │ Created: Feb 2026  │     │
│  └─────────────┘ └────────────────────┘     │
│                                             │
│  [View Reading →]                           │
│                                             │
└─────────────────────────────────────────────┘
```

---

CARD DESIGN DETAILS:

Structure:
- Surface-2 background, standard border, 16px radius
- 24px padding
- Full width within content column

Top row (identity):
- Left: Daymaster abstract symbol (48×48) in element color
  - For compatibility: two symbols with ⟷ connector
- Right: 
  - Name (sans 600, 17px, white)
  - Pattern name (sans 400, 14px, text-muted)
  - Element + birth date (sans 400, 13px, text-muted)

Middle row (badges + meta):
- Tier badge:
  - "FULL READING": gold text, gold-tint bg, 4px radius, 12px sans 600
  - "PROLOGUE": green text, green-tint bg, 4px radius
  - "COMPATIBILITY": blue text, blue-tint bg, 4px radius
- Year badge: "2026" in surface-2 with border (if applicable)
- Date info: "Last opened: X" or "Created: X" (sans 400, 13px, text-muted)

Bottom row (actions):
- Primary action: "Continue Reading →" or "View Reading →" (gold text link, 14px, sans 600)
- Secondary action (if upgradeable): "Upgrade to Full — $15.99" (secondary button, gold border)
- Actions are right-aligned on PC, full-width stacked on mobile

HOVER STATE (PC only):
- Card border transitions to gold-dim
- Subtle gold-tint background overlay
- Primary action text brightens to gold-light

---

EMPTY STATE (no readings yet):

```
[Center of page]

  [Orbital symbol — 120×120, simplified, gold at 40% opacity]
  
  "No readings yet."
  (serif 400, 24px, white)
  
  "Start your first analysis to see it here."
  (sans 400, 15px, text-secondary)
  
  [Button: "Create Your First Reading →"]
  (primary gold, 48px height, max-width 300px)
```

---

PC SPECIFICS (1440×900):
- Content max-width: 720px, centered
- Cards have 16px gap between them
- "New Reading" button in header: secondary style (gold border)
- Page title area: 48px margin-bottom before cards
- Cards show actions inline (horizontal)

MOBILE SPECIFICS (390×844):
- 20px horizontal padding
- Cards are full-width
- "New Reading" button: floating action button (FAB) in bottom-right
  - 56×56px circle, gold fill, + icon
  - 20px from right edge, 20px above safe area
  - Subtle shadow: rgba(201,169,110,0.3) 0 4px 16px
- Card actions stack vertically
- Scroll behavior: natural, no pagination
- Pull-to-refresh gesture supported (implied)

---

HEADER BEHAVIOR:
- Sticky on scroll
- "My Readings" replaces normal header on this page
- Back arrow (←) returns to last reading or home
- PC: full header with logo left, "New Reading" button right
- Mobile: simplified header, FAB replaces button

SORTING:
- Default: most recently opened first
- No explicit sort controls (keep it simple)
- Compatibility readings mixed in chronologically

DESIGN PRINCIPLES:
1. This is a utility screen — prioritize scanability over beauty
2. Each card should communicate: WHO (name), WHAT (tier), WHEN (date) at a glance
3. The upgrade path from Prologue → Full Reading should be visible but not pushy
4. Element colors on symbols create visual variety across cards
5. Empty state should encourage, not feel empty

NO:
- Search or filter controls (premature for MVP)
- Bulk actions or multi-select
- Social features or sharing from this screen
- Reading analytics or stats
- Any Eastern philosophy terms or characters

FORMAT:
- Frame 1: 1440×900 (PC, 2-3 reading cards)
- Frame 2: 390×844 (Mobile, 2-3 reading cards)
```
