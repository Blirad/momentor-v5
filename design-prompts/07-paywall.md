# 07 — Paywall / Full Reading Gate Prompt (Variant AI)

## Prompt

```
Design the Paywall screen and the Full Reading entry for Momentor. This is the premium upgrade moment — it must feel like unlocking a deeper layer of analysis, not like hitting a wall.

DELIVER THREE FRAMES:
- Frame 1: Paywall Modal (PC, 1440×900)
- Frame 2: Paywall Full-Screen (Mobile, 390×844)
- Frame 3: Full Reading Entry — first section after purchase (Mobile, 390×1200)

GLOBAL STYLE: Follow established style board.

---

FRAME 1 & 2: PAYWALL

The paywall appears when a user taps a locked chapter or the "Unlock" CTA from the free reading.

TWO MODES:
- PC: Modal overlay (centered card on darkened background)
- Mobile: Full-screen takeover (no modal — uses entire viewport)

---

PC PAYWALL MODAL:

Background: #0d0b1e at 80% opacity overlay on blurred reading content

Modal card:
- Max-width: 480px, centered vertically and horizontally
- Background: #110f27 (surface-1)
- Border: rgba(255,255,255,0.08)
- Radius: 20px
- Padding: 40px

Layout (top to bottom):
```
[Close button — top right, X icon, text-muted]

[Signature Object — small orbital, 120×120px]
  Simplified version of hero orbital
  Gold central glow, 3 rings
  Centered

[Headline — serif 400, 28px, center, white]:
"See the full picture."

[Subtext — sans 400, 15px, center, text-secondary]:
"Your Prologue revealed your core pattern.
 The Full Reading decodes your entire year."

[Divider — 1px, rgba(255,255,255,0.06), full width]

[What's Included — Checklist]

  Each item:
  ✦ icon (gold, 14px) + text (sans 400, 15px, text-primary)
  
  ✦ Complete 2026 forecast — month by month
  ✦ 10 life domains analyzed in depth
  ✦ Personalized monthly energy flow
  ✦ Today's energy — updated daily pattern
  ✦ Shareable insight cards
  
  Spacing: 12px between items
  Left-aligned within centered container

[Divider]

[Price Block — centered]
  Price: "$15.99" (serif 500, 36px, gold)
  Label: "one-time payment" (sans 400, 13px, text-muted)

[CTA Button — full width within modal]
  "Unlock Full Reading →"
  Gold filled, 52px height, 15px Inter 600

[Trust Line — centered]
  "No subscription. Yours to keep." (sans 400, 13px, text-muted)
  
[Payment icons — small, 40% opacity]
  Visa / Mastercard / Apple Pay logos (very subtle)
```

---

MOBILE PAYWALL (Full Screen):

Same content as PC modal but adapted:
- No modal card — content directly on #0d0b1e background
- Full viewport, scrollable if needed
- Close button: "←" back arrow, top-left
- Signature object: 160×160px (larger since we have more space)
- CTA: fixed to bottom with safe area padding
- Content scrolls above fixed CTA
- More breathing room between elements (32px gaps)

Layout:
```
[Header: ← Back          ✦ Momentor]
─────────────────────
            [Orbital: 160×160px]
            
            "See the full picture."
            (serif 400, 28px)
            
            "Your Prologue revealed your core
             pattern. The Full Reading decodes
             your entire year."
            (sans 400, 15px, text-secondary)
            
─── divider ───
            
            ✦ Complete 2026 forecast
            ✦ 10 life domains analyzed
            ✦ Monthly energy flow
            ✦ Today's energy
            ✦ Shareable insight cards
            
─── divider ───
            
            $15.99
            one-time payment

─────────────────────
[Sticky CTA: "Unlock Full Reading →"]
[Trust: "No subscription. Yours to keep."]
[Safe area: 34px]
```

---

FRAME 3: FULL READING ENTRY (after purchase, Mobile)

This screen appears immediately after successful payment. It's a celebratory transition into the premium content.

```
[Header: ✦ Momentor]
─────────────────────
[Success Moment — Center]
  
  Checkmark animation (gold circle + check, 64×64px)
  
  "Your Full Reading is ready."
  (serif 400, 24px, white, center)
  
  "Personalized for [Name]"
  (sans 400, 14px, text-muted, center)

─────────────────────
[Updated Chapter Navigation]
  
  All 4 chapters now UNLOCKED:
  
  Card 1: "Chapter I — Who You Are"        [✓ Read]
  Card 2: "Chapter II — Life Phases"       [✓ Read]
  Card 3: "Chapter III — 2026 Forecast"    [→ NEW]
  Card 4: "Chapter IV — Today's Energy"    [→ NEW]
  
  NEW chapters have gold left border + subtle gold-tint background
  Read chapters have checkmark + standard styling
  
  Each card: surface-2 fill, border, 12px radius, 20px padding
  Arrow/check: right-aligned
  
─────────────────────
[Quick Preview — 2026 Headline]

  "2026 OVERVIEW" (sans 500, 13px, gold, uppercase)
  
  Hero stat cards (3 in a row):
  ┌──────┐ ┌──────┐ ┌──────┐
  │ Peak │ │ Key  │ │ Watch│
  │Month │ │Theme │ │ Area │
  │      │ │      │ │      │
  │ June │ │Growth│ │Career│
  └──────┘ └──────┘ └──────┘
  
  Each: surface-2, border, 12px radius
  Stat label: sans 500, 12px, text-muted, uppercase
  Stat value: serif 500, 20px, white

─────────────────────
[CTA: "Start Chapter III →"]
  Full-width gold, 52px
```

---

DESIGN PRINCIPLES:

1. PAYWALL:
   - Never use "Buy" — use "Unlock"
   - Emphasize what they GET, not what they're missing
   - The orbital object creates continuity with the brand
   - Price is prominent but not aggressive
   - Trust signals (no subscription, payment icons) reduce friction
   - Transition from free to paywall should feel like a natural next step

2. POST-PURCHASE:
   - Celebrate briefly, then get to content fast
   - Show what's new with visual distinction (gold borders on new chapters)
   - Don't make them re-navigate — offer direct entry to new content
   - The 3-stat preview creates immediate curiosity

3. NO:
   - Comparison tables (free vs paid)
   - Urgency tactics ("Limited time!", "X people viewing")
   - Discount codes or strike-through pricing
   - Multiple plan options on this screen
   - Any reference to Eastern philosophy terms

FORMAT:
- Frame 1: 1440×900 (PC paywall modal)
- Frame 2: 390×844 (Mobile paywall full-screen)
- Frame 3: 390×1200 (Mobile post-purchase entry)
```
