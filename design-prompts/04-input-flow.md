# 04 — Input Flow Prompt (Variant AI)

## Prompt

```
Design the input flow for Momentor, a premium birth-data pattern analysis web app. This is a 2-step form where users enter their birth information.

DELIVER TWO FRAMES:
- Frame 1: PC (1440×900) — Step 1 and Step 2 side by side or as a progression
- Frame 2: Mobile (390×844) — Step 1 full screen

GLOBAL STYLE: Follow the established style board exactly.
- Background: #0d0b1e
- Typography: Cormorant Garamond (display), Inter (UI)
- Gold: #c9a96e
- Cards: rgba(255,255,255,0.04) fill, rgba(255,255,255,0.08) border, 12px radius

---

STEP 1 — BASIC INFO

Section title (serif, 28px, white):
"Let's map your pattern."

Subtitle (sans, 15px, text-secondary):
"We need your birth details to generate your unique analysis."

FORM FIELDS:

1. NAME
   - Label: "Name" (sans 500, 13px, uppercase, text-muted, letter-spacing 0.04em)
   - Input: Full width, surface-2 fill, border, 48px height, 16px text
   - Placeholder: "Enter your name" (text-muted)

2. BIRTH DATE (3 fields in a row)
   - Label: "Date of Birth"
   - Three select dropdowns side by side:
     - Month (Jan–Dec)
     - Day (1–31)
     - Year (1940–2010)
   - Each: surface-2 fill, border, 48px height
   - Layout: 3 columns with 12px gap

3. GENDER
   - Label: "Gender"
   - Three toggle buttons in a row:
     - "Male" | "Female" | "Other"
   - Default: none selected
   - Selected state: gold border, gold-tint fill, gold text
   - Unselected: surface-2 fill, border, text-secondary
   - Each: 48px height, equal width, 8px radius

4. CTA BUTTON
   - "Continue →" (primary gold, full width on mobile, 280px on PC)
   - 52px height, 15px Inter 600
   - Disabled state: 40% opacity until all fields filled

STEP INDICATOR:
- Two dots or a "Step 1 of 2" label
- Minimal, text-muted color
- Position: above the section title

---

STEP 2 — TIME & LOCATION (optional refinement)

Section title (serif, 28px):
"Refine your analysis."

Subtitle (sans, 15px, text-secondary):
"Birth time and location add precision. Skip if unknown."

FORM FIELDS:

1. BIRTH TIME
   - Label: "Birth Time (optional)"
   - Two select dropdowns: Hour (1–12 + AM/PM) and Minute (00, 15, 30, 45)
   - "I don't know my birth time" checkbox below
     - When checked: time fields become disabled (50% opacity)
   - Layout: 2 columns + AM/PM toggle

2. BIRTH CITY
   - Label: "Birth City (optional)"
   - Search input with autocomplete dropdown
   - Icon: location pin (thin stroke, left side)
   - GPS button: "Use my location" small text link below input
   - Autocomplete dropdown: surface-1 fill, max 5 results, each 44px height

3. CTA BUTTON
   - "Generate My Analysis →" (primary gold)
   - Full width on mobile, 320px on PC
   - Below: "This takes about 5 seconds" (text-muted, 13px)

4. SKIP OPTION
   - "Skip — analyze with date only" (text link, gold-dim, 14px)
   - Below the CTA, centered

---

PC LAYOUT (1440×900):
- Form container: max-width 520px, centered
- Card wrapper: surface-2 background, 32px padding, 16px radius
- Generous vertical spacing (24px between fields)
- Left-aligned labels
- Step transition: slide-left animation

MOBILE LAYOUT (390×844):
- Full-screen form, 20px horizontal padding
- No card wrapper (form fields directly on dark background)
- Sticky bottom CTA (fixed to bottom with 20px padding, above safe area)
- Scrollable content area above sticky CTA
- Touch-friendly: all targets minimum 48px height

FORM STATES:
- Default: border at rgba(255,255,255,0.08)
- Focus: border transitions to gold (#c9a96e) with subtle gold glow
- Filled: border remains white 0.12, text-primary
- Error: border #f87171, error message below in #f87171, 13px
- Disabled: 40% opacity

VALIDATION:
- Inline error messages below fields
- "Please enter your name" / "Please select a complete date"
- Error icon: small circle-exclamation, thin stroke, red

PROGRESS FEEL:
The form should feel fast and purposeful. No decorative elements within the form. The only visual personality comes from typography and spacing. This is a data collection instrument, not a quiz.

FORMAT: Two frames — 1440×900 (PC) and 390×844 (Mobile), both showing Step 1.
```
