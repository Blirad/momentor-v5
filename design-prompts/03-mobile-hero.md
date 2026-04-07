# 03 — Mobile Hero Prompt (Variant AI)

## Prompt

```
Design the mobile hero screen for Momentor, a premium birth-data pattern analysis web app.

VIEWPORT: 390×844 (iPhone 14 Pro, full screen)

GLOBAL STYLE (follow exactly):
- Background: #0d0b1e
- Typography: Cormorant Garamond (display), Inter (UI)
- Gold accent: #c9a96e
- All tokens from Global Style Board apply

LAYOUT STRUCTURE (top to bottom):
```
[Status Bar — system]
─────────────────────
[Header: 56px]
  Left: ✦ Momentor
  Right: hamburger icon (thin stroke)
─────────────────────
[Signature Object: ~280×280px]
  Centered
  Scaled version of PC hero's orbital diagram
  — Simpler: fewer rings, same essence
  — Central gold glow maintained
  — Element-color orbital lines
  — Breathing animation implied
─────────────────────
[Text Block: centered]
  
  Headline (serif 300, 34px):
  "Your birth data.
   Decoded."
  
  Subheadline (sans 400, 15px):
  "Momentor maps the hidden
   patterns in your birth date."
  
  [CTA: Full-width gold button]
  "Decode Your Pattern"
  (52px height, 15px Inter 600)
  
  Trust line (muted, 12px):
  "518,400 unique combinations"
─────────────────────
[Scroll indicator: subtle chevron]
```

KEY DIFFERENCES FROM PC:
1. Signature object moves ABOVE the text (visual-first on mobile)
2. Text is center-aligned (not left-aligned like PC)
3. CTA is full-width with 20px horizontal margin
4. Object is smaller (280px) but still the focal point
5. No visible "My Readings" or "Get Full Reading" in header (moved to menu)
6. Subheadline is shorter (2 lines max)

HEADER (MOBILE):
- Height: 56px
- Background: transparent (becomes #0d0b1e with blur on scroll)
- Left: ✦ Momentor (Inter 600, 15px)
- Right: Menu icon (3-line, thin stroke, white 70% opacity)
- Horizontal padding: 20px

SIGNATURE OBJECT (MOBILE):
- 280×280px centered
- Margin-top: 40px from header
- Simplified version of the PC orbital diagram:
  - 3 concentric rings instead of 5+
  - Same element-color thin lines
  - Central gold point maintained
  - Fewer data-point nodes
  - Still suggests motion and precision
- Margin-bottom: 40px to text

TEXT BLOCK:
- Padding: 0 24px
- Headline: Cormorant Garamond 300, 34px, center, white, line-height 1.2
- Gap: 16px
- Subheadline: Inter 400, 15px, center, text-secondary, line-height 1.6
- Gap: 32px
- CTA: Full width (minus 24px padding each side), gold filled, 52px height
- Gap: 16px
- Trust line: Inter 500, 12px, text-muted, center, uppercase

BACKGROUND:
- Same as PC: faint radial glow from signature object center
- No additional decorative elements
- Clean, breathable

SCROLL INDICATOR:
- Small downward chevron, gold-dim color
- 24px below trust line
- Subtle pulse animation implied

BOTTOM SAFE AREA:
- 34px safe area for home indicator

MOOD:
The mobile hero should feel like opening a premium fintech app for the first time — confident, clean, one clear action. The signature object draws the eye, the headline clarifies the value, the CTA captures the intent.

FORMAT: 390×844, full mobile screen, pixel-perfect.
```
