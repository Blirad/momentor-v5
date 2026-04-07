# 08 — Compatibility Reading Offer Prompt (Variant AI)

## Prompt

```
Design the Compatibility Reading offer and entry screen for Momentor. This is a secondary paid product ($12.99) that analyzes the pattern dynamics between two people.

DELIVER TWO FRAMES:
- Frame 1: Compatibility Offer Card / Upsell (PC 1440×900, shown within reading flow)
- Frame 2: Compatibility Entry (Mobile 390×1200, after purchase)

GLOBAL STYLE: Follow established style board.

---

CONTEXT:
The Compatibility Reading appears as a contextual offer AFTER the user has completed (or is completing) their Full Reading. It's not a hard upsell — it's a natural extension: "Now that you know your pattern, see how it interacts with someone else's."

---

FRAME 1: COMPATIBILITY OFFER (PC, in-flow)

This appears as an inline section within the reading page, between chapters or at the end of the Full Reading. NOT a modal or popup.

Layout within 680px content column:
```
[Divider — decorative, thin gold line with small diamond center]

[Compatibility Section — surface-1 background, 20px radius, 40px padding]

  [Visual: Two Orbital Diagrams Overlapping]
  — Two simplified orbital systems (3 rings each)
  — Overlapping at center with shared golden intersection point
  — Left orbit: user's element color (e.g., green for Wood)
  — Right orbit: neutral/silver (representing the other person)
  — Size: ~320×180px, centered
  — Feels like: two systems being compared, Venn-diagram energy

  [Headline — serif 400, 26px, white, center]:
  "How do your patterns interact?"

  [Subtext — sans 400, 15px, text-secondary, center, max-width 420px]:
  "Add someone's birth data and discover the dynamics between your patterns — where you amplify, where you challenge, and when timing aligns."

  [What's Included — 2-column grid or inline list]
  
  Left column:
  ✦ Relational dynamics map
  ✦ Elemental compatibility score
  ✦ Mutual strength & friction points
  
  Right column:
  ✦ Timing alignment windows
  ✦ Communication pattern analysis
  ✦ Shared growth opportunities
  
  Style: sans 400, 14px, text-primary
  ✦ icon in gold

  [Price + CTA — centered]
  
  "$12.99" (serif 500, 28px, gold)
  "one-time" (sans 400, 13px, text-muted)
  
  [Button: "Add a Person →"]
  Secondary style: transparent, gold border, gold text
  Max-width: 280px, 48px height, centered
  
  [Trust: "No subscription required." — sans 400, 12px, text-muted]

[End of section]
[Divider]
```

---

FRAME 2: COMPATIBILITY ENTRY (Mobile, after purchase/initiation)

After tapping "Add a Person", user enters the second person's data. Then they see the compatibility result entry.

```
[Header: ✦ Momentor    ← Back]
─────────────────────

[Two-Person Header — Side by side]

  ┌──────────┐  ⟷  ┌──────────┐
  │  User's   │     │  Person   │
  │  Symbol   │     │  Symbol   │
  │  (48×48)  │     │  (48×48)  │
  │           │     │           │
  │  "Alex"   │     │  "Jordan" │
  │  Architect│     │  Catalyst │
  │  Wood     │     │  Fire     │
  └──────────┘     └──────────┘

  Connection symbol (⟷): 
  Thin gold line connecting the two, with a subtle pulse point at center
  
  Each person card: surface-2, border, 12px radius, 16px padding
  Symbol: abstract daymaster glyph in element color
  Name: sans 500, 15px, white
  Pattern name: sans 400, 13px, text-muted
  Element: element-color dot + text

─────────────────────
[Compatibility Score — Visual]

  Circular gauge or radial indicator:
  — Outer ring: gradient from user's element color to partner's element color
  — Fill level indicates compatibility intensity (not "good/bad" — just intensity)
  — Center: score or label
  
  Example:
  Center text: "Dynamic Tension" (serif 500, 20px, white)
  Sub-label: "High interaction energy" (sans 400, 13px, text-muted)
  
  NOTE: This is NOT a percentage score. It's a qualitative label.
  Labels like: "Deep Resonance" / "Creative Friction" / "Steady Foundation" / "Dynamic Tension"

─────────────────────
[Key Dynamics — 3 Cards]

  Card 1: "Where You Amplify"
  Icon: two arrows pointing up (thin, gold)
  Brief text: "Your methodical planning meets their spontaneous energy..."
  (sans 400, 14px, text-secondary)
  
  Card 2: "Where You Challenge"
  Icon: two arrows crossing (thin, amber)
  Brief text: "Your need for structure may feel restrictive to their flow..."
  
  Card 3: "Timing Windows"
  Icon: two circles overlapping (thin, blue)
  Brief text: "Peak alignment periods in 2026: March, August, November"
  
  Each card: surface-2, border, 12px radius, 20px padding
  Icon: 32×32, element-color themed
  Title: sans 600, 15px, white
  Text: sans 400, 14px, text-secondary

─────────────────────
[CTA: "Read Full Compatibility Analysis →"]
  Full-width gold, 52px

─────────────────────
[Also Available — subtle cross-sell if they don't have Full Reading]

  Small card, surface-2, text-muted:
  "Don't have your Full Reading yet?"
  "Get the complete analysis of your own pattern → $15.99"
  [Text link in gold]
```

---

DESIGN PRINCIPLES:

1. OFFER POSITIONING:
   - It's a companion product, not an upsell
   - Framed as "what happens when two patterns meet" — curious, not salesy
   - The overlapping orbital visual creates an intuitive metaphor
   - Secondary button style (not gold fill) signals this is optional

2. COMPATIBILITY RESULT:
   - NEVER frame as "good" or "bad" compatibility
   - Use neutral-positive language: dynamics, interaction, tension, resonance
   - The circular gauge is qualitative, not a number out of 100
   - Show both strengths AND challenges — honest analysis builds trust

3. VISUAL DISTINCTION:
   - The two-orbital overlap is the signature visual for compatibility
   - Element colors differentiate the two people
   - The connection line/point suggests the interaction zone

4. NO:
   - Heart icons or romantic imagery
   - Percentage compatibility scores
   - "Soulmate" or "Twin flame" language  
   - Comparison to zodiac sign compatibility
   - Any reference to Eastern philosophy terms (no "五行", no "상생/상극")

FORMAT:
- Frame 1: 1440×900 (PC, offer within reading flow)
- Frame 2: 390×1200 (Mobile, compatibility result entry)
```
