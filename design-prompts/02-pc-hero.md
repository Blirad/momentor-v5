# 02 — PC Hero Prompt (Variant AI)

## Prompt

```
Design the desktop hero section for Momentor, a premium birth-data pattern analysis web app.

VIEWPORT: 1440×900 (above the fold)

GLOBAL STYLE (already established — follow exactly):
- Background: #0d0b1e with subtle radial gradient glow (purple-gold, very faint)
- Typography: Cormorant Garamond for display, Inter for UI
- Accent: #c9a96e gold, used sparingly
- Full style tokens: see Global Style Board

LAYOUT STRUCTURE:
```
[Header Bar]
─────────────────────────────────────────────
[Left: Text Block]          [Right: Signature Object]
                            
  Logo: ✦ Momentor          Abstract orbital diagram
  (Inter 600, 16px,          — NOT a chart or infographic
   gold accent on ✦)         — NOT an explanatory visual
                              — A signature brand object
  Headline (serif 300):       — Radial, layered, animated-feel
  "Your birth data.           — Uses element colors subtly
   Decoded."                    as orbital paths
                              — Suggests precision analysis
  Subheadline (sans 400):     — Think: orrery meets data viz
  "Momentor maps the          — Roughly 500×500px area
   hidden patterns in        
   your birth date —         
   no astrology,             
   no guesswork."            
                             
  [CTA Button: "Decode Your Pattern" →]
  (Primary gold, Inter 600)
  
  Trust line (muted, 13px):
  "518,400 unique pattern combinations analyzed"
─────────────────────────────────────────────
```

HEADER BAR:
- Sticky, transparent background with blur on scroll
- Left: ✦ Momentor logo
- Right: "My Readings" link (text only, sans 500) + "Get Full Reading" button (primary gold, small)
- Height: 64px
- Max-width: 1200px centered

HERO LEFT (TEXT BLOCK):
- Max-width: 520px
- Headline: Cormorant Garamond 300, 56px, line-height 1.15, white
- Subheadline: Inter 400, 17px, text-secondary, line-height 1.6, max-width 420px
- CTA: Gold filled button, 52px height, 24px horizontal padding, 15px text
- Trust line: Inter 500, 13px, text-muted, uppercase, letter-spacing 0.05em
- Vertical spacing: 24px between elements

HERO RIGHT (SIGNATURE OBJECT):
This is the most important visual element. It must NOT be:
- A pie chart or data visualization
- An educational diagram explaining a system
- A zodiac wheel or mandala
- Chinese characters or Eastern symbols
- A screenshot or UI mockup

It MUST be:
- An abstract radial/orbital composition
- Layered concentric rings with varying opacity
- Subtle dots or nodes along orbital paths (suggesting data points)
- Uses element colors (#4ade80, #f87171, #d97706, #94a3b8, #60a5fa) as thin orbital lines
- A central glowing point (gold) suggesting the "core pattern"
- Feels like a precision instrument — an orrery, a particle accelerator diagram, or a stellarium
- Has depth through layered opacity (front rings brighter, back rings dimmer)
- Suggests motion even in a static frame (arcs, trajectories)
- Size: ~480×480px, centered in right half

BACKGROUND EFFECTS:
- Very subtle radial gradient from center of signature object: rgba(201,169,110,0.04)
- Faint grid pattern at 5% opacity (suggesting analytical precision)
- No stars, no nebula, no space imagery

SPACING:
- Header to hero content: 120px
- Left block vertically centered in hero area
- Horizontal gap between left and right: 80px minimum

MOOD:
Think Bloomberg Terminal's aesthetic confidence meets Stripe's clarity meets a scientific instrument's precision. The user should think "this is a serious analysis tool" not "this is a horoscope site."

FORMAT: 1440×900, full hero section, pixel-perfect.
```
