# MedVault — Premium Healthcare UI/UX Redesign — Implementation Prompt

> **How to use this file:** Paste this entire document as the first message to a new Claude session that has access to the MedVault codebase (the `medical-data-decentralisation-main` repo). It is self-contained — it describes the current system, the target design system, and page-by-page requirements. Do not summarize or skip sections; execute them in the order given.

---

## 0. ROLE

You are acting as a senior Product Designer, Design System Architect, and Frontend Engineer embedded in the MedVault codebase. You are performing a **UI/UX-only redesign** of an existing, working, production-grade application. You are not building a new app and you are not touching backend logic, routes, database schema, encryption, or business logic in any way that changes behavior.

---

## 1. WHAT THIS PROJECT IS (ground truth — do not deviate)

MedVault is a decentralized, patient-owned medical records platform:

- **Backend:** Flask (Python), PostgreSQL, RSA-4096 + AES-256-GCM end-to-end encryption, Argon2id key derivation, JWT auth with refresh-token rotation, zero-trust access model (doctors get time-limited wrapped-key access, patients approve/deny/revoke).
- **Three portals sharing one Flask template layer:**
  - `portals/landing.py` — marketing/landing page + auth + the majority of patient- and doctor-facing page routes (dashboard, health record, EMR, prescriptions, lab reports, notes, appointments, access requests, audit log, profile, my-patients, patient-detail, encounter-detail).
  - `portals/patient_portal.py` — JSON API layer for the patient-side SPA-ish interactions (registration, approvals, QR transfer, OTP, EMR proxy).
  - `portals/doctor_portal.py` — JSON API layer for doctor-side interactions.
- **Templates** live in `portals/templates/*.html`, all extending `base.html`, which conditionally includes `partials/sidebar.html` and `partials/topbar.html` when `session.get('logged_in')` is true.
- **Styling** is two hand-authored CSS files: `portals/static/css/base.css` (tokens, reset, typography, layout primitives, utilities) and `portals/static/css/components.css` (all UI components). No CSS framework, no build step — plain CSS with custom properties.
- **JS** is a single vanilla file, `portals/static/js/app.js`, handling: flash-message auto-dismiss, sidebar active-state, fade-in-on-scroll for stat cards, tab switching (`[data-tab-group]`), auth role tab switching, inline confirm dialogs (`[data-confirm-trigger]` / `[data-confirm-cancel]`), input blur validation feedback, clickable table rows (`[data-href]`), copy-to-clipboard buttons (`[data-copy]`), and password visibility toggle.
- **Roles:** `patient`, `doctor`, and a third `admin`/receptionist-style role — each gets a different sidebar navigation set (see `partials/sidebar.html`).

### Full route/page inventory (do not remove or rename any of these)

| Route | Template | Role(s) |
|---|---|---|
| `/` | `landing.html` | public |
| `/dashboard` | `dashboard.html` | patient / doctor / admin (content varies by role) |
| `/health-record` | `health_record.html` | patient |
| `/emr` | `emr.html` | patient |
| `/prescriptions` | `prescriptions.html` | patient |
| `/lab-reports` | `lab_reports.html` | patient |
| `/notes` | (patient notes view + doctor "add note" form, same route different role behavior) | patient / doctor |
| `/access-requests` | `access_requests.html` | patient |
| `/audit` | `audit_log.html` | patient / doctor |
| `/appointments` | `appointments.html` | patient / doctor / admin |
| `/profile` | `profile.html` | all |
| `/encounter/<id>` | `encounter_detail.html` | patient / doctor |
| `/my-patients` | `my_patients.html` | doctor |
| `/patient-detail` | `patient_detail.html` | doctor |
| `/doctor/prescriptions` | `doctor_prescriptions.html` | doctor |
| `/doctor/lab-reports` | `doctor_lab_reports.html` | doctor |
| `/doctor/notes/<code>` (view) | `doctor_notes.html` | doctor |

Auth is handled inline on `/` (login/register forms with role tab switcher — see `.auth-tab-switcher`, `.auth-role-panel` in app.js), not a separate page.

### Current visual identity (being replaced)

- **Dark theme.** Root surfaces `--s0:#07090F` → `--s3:#1A2236`. Accent palette is Purple (`--p1`–`--p6`), Gold (`--g1`–`--g6`), Teal (`--t1`–`--t6`), Crimson (`--r1`–`--r6`) — a "vault / crypto" aesthetic (there's literally a `.vault-visual`, `.vault-core`, `.vault-ring-*` decorative component on the landing page).
- Font: Inter (sans) + JetBrains Mono (for codes/IDs — `.type-mono`).
- Fixed 240px sidebar (`.page-shell`, `.page-main` with `margin-left: 240px`), topbar, `.page-content` max-width 1200px.
- Component inventory already in `components.css`: `.card` / `.card-elevated` / `.card-interactive`, `.btn-primary` / `.btn-secondary` / `.btn-ghost` / `.btn-danger` / `.btn-sm`, `.badge` + role/status variants (`badge-patient`, `badge-doctor`, `badge-admin`, `badge-pending`, `badge-approved`, `badge-denied`, `badge-expired`, `badge-cancelled`, `badge-completed`, `badge-scheduled`, `badge-verified`, `badge-encrypted`), `.data-table`, `.stat-card` (+ `-purple`, `-teal`, `-accent` variants), `.stat-bar`, `.alert` (success/error/warning/info), `.input-field`/`.input-label`/`.input-hint`/`.input-error`, `.tabs`/`.tab-item`/`.tab-count`, `.empty-state`, `.skeleton`, `.spinner`, `.inline-confirm`, `.filter-bar`/`.filter-select`, `.note-card`, `.arch-diagram` (landing page architecture visual), auth shell (`.auth-shell`, `.auth-left`, `.auth-right`, `.auth-form`).

This inventory is your refactor checklist — every one of these must be redesigned and none may be dropped or left half-migrated.

---

## 2. REDESIGN BRIEF

### 2.1 Vision

Redesign MedVault's entire visual and verbal identity into a **premium, light-themed healthcare SaaS product** — the kind of polish and restraint you'd expect from Stripe, Linear, Notion, Apple Health, or Google Health. Not flashy, not "gamer/crypto vault" styling, not a college project. Every screen should communicate **trust, security, clarity, and calm competence** at a glance.

### 2.2 Non-negotiable constraints

1. **Zero functional regression.** Every route, form, API call, `data-*` JS hook, template variable (`session.get(...)`, `request.path`, Jinja loops/conditionals), and backend contract stays exactly as-is. You are re-skinning and re-structuring markup/CSS/copy, not rewriting application logic.
2. **Do not touch:** `server/`, `common/`, `client/`, `doctor/`, encryption logic, JWT/session logic, API routes/payloads, database schema. If a visual change seems to require a backend change, flag it instead of making it.
3. **Preserve all Jinja template logic** (role branching in `sidebar.html`, flash message categories, `{% block %}` structure in `base.html`). Restructure the HTML/CSS *within* that logic, don't remove the logic.
4. **Refactor, don't duplicate.** Introduce a clean design-token layer and reusable component classes; eliminate one-off inline styles currently scattered in templates (e.g., inline `style="..."` attributes found in `sidebar.html`, `dashboard.html`, `health_record.html`, `patient_detail.html`).
5. Every existing `data-tab-group`, `data-confirm-trigger`, `data-confirm-cancel`, `data-href`, `data-copy`, `data-toggle-password` hook in `app.js` must keep working against the new markup — update `app.js` only if a selector's DOM shape changes, never remove the behavior.

---

## 3. NEW DESIGN SYSTEM

### 3.1 Color tokens (replace all tokens in `base.css` `:root`)

Design a full light-theme token set with this structure (naming can stay close to the current `--s*`, `--b*`, `--tx*` convention so templates using `var(--tx1)` etc. keep working after value swaps — but you must audit every usage site since some current combinations rely on dark-surface contrast logic that won't survive a naive value swap):

- **Surfaces:** pure white base, 2–3 steps of very subtle cool-gray (`#FFFFFF`, `#F8FAFC`, `#F1F5F9`) for elevation — never gray-on-gray murk.
- **Borders:** hairline, low-contrast cool grays (`#E2E8F0`, `#CBD5E1`) — borders should feel like structure, not decoration.
- **Primary (Medical Blue):** a confident, accessible blue family (5–6 steps, e.g., `#EFF6FF` → `#1D4ED8` → `#1E3A8A`) used for primary actions, active nav states, focus rings, links, and the "encrypted/secure" visual language (replacing the current purple/gold "vault" motif).
- **Secondary accent:** a muted slate/graphite for secondary emphasis (replacing teal-as-secondary).
- **Semantic colors:** success (green), warning (amber), danger (red), info (blue-gray) — each with a background tint, border, and text-safe foreground pairing (for `.alert-*` and `.badge-*` variants). Every pairing must pass WCAG AA (4.5:1 body text, 3:1 large text/icons).
- **Text:** `--tx1` (near-black, primary), `--tx2` (slate, secondary), `--tx3` (muted, tertiary/labels), `--tx4` reserved for on-color text (e.g., white text on filled blue buttons). Never reuse the old dark-theme logic where `--tx1` was near-white.
- **Charts/data-viz:** define a categorical palette (blues, teals, ambers — no neon) for stat bars, trend lines, and any future charts.
- Keep the token block organized under clear comment headers exactly like the current file so it's scannable: Surfaces / Borders / Primary / Secondary / Semantic / Text / Typography / Spacing / Radius / Shadows / Transitions.

### 3.2 Typography

- Keep **Inter** for UI text (already loaded, already excellent for this use case) — do not introduce a new webfont just for novelty. Keep **JetBrains Mono** only for genuinely code-like values (patient IDs, doctor codes, audit hashes) via `.type-mono`.
- Rebuild the type scale (`--t-xs` → `--t-4xl`) with slightly more restrained top-end sizes appropriate to a dashboard-dense app (the current `--t-4xl: 49px` is landing-page-hero-only; don't let it leak into app-shell headers).
- Line-height: 1.5–1.6 for body copy, 1.15–1.3 for headings. Letter-spacing: slightly negative on large headings only (as today), neutral elsewhere.
- Every `.type-*` utility class name should be preserved (`type-display`, `type-h1`, `type-h2`, `type-h3`, `type-label`, `type-caption`, `type-mono`) — only their computed values and colors change.

### 3.3 Spacing, radius, shadow, motion

- Keep the existing 4px-based spacing scale (`--sp-1` … `--sp-24`) — it's sound; don't reinvent it.
- Radius: introduce a slightly more generous, consistent scale (e.g., 8px small controls, 12–14px cards, 20px+ large surfaces/modals) — current `--r-sm/--r-md` (6/10px) reads a bit sharp/dense for a "premium" feel.
- Shadows: **replace the current heavy black shadows** (`rgba(0,0,0,0.4–0.6)`) with soft, low-opacity, cool-tinted shadows appropriate for light UI (e.g., `0 1px 2px rgba(15,23,42,0.04)`, `0 8px 24px rgba(15,23,42,0.08)`). Never let a shadow read as "muddy" or heavy.
- Motion: keep the existing easing/duration tokens (`--ease`, `--dur-fast/base/slow`) as the timing contract; apply them to hover/focus/press states, tab switches, modal/toast entry, and skeleton shimmer. Nothing should exceed ~300ms. No bouncing, no parallax, no attention-seeking motion.

### 3.4 Iconography

- Continue using the current inline-SVG, stroke-based icon approach already present throughout `sidebar.html` and templates (Heroicons-style, `stroke-width="1.5"`, `viewBox="0 0 24 24"`). Keep one consistent stroke width across every icon in the app (audit and fix any inconsistent ones you find). Do not switch to a filled or mixed icon style, and do not introduce a new icon library/dependency.

---

## 4. COMPONENT-LEVEL SPECIFICATION

Redesign every component below as a token-driven, reusable class in `components.css`. For each, specify (in your actual output, not just this prompt): default / hover / active / focus-visible / disabled states, and how it looks carrying each semantic variant where applicable.

- **Buttons** — `.btn-primary` (solid medical blue, white text), `.btn-secondary` (outline/tinted), `.btn-ghost` (text-only, for low-emphasis actions like table row actions), `.btn-danger` (revoke access, delete note, deny request), `.btn-sm`. Clear `:focus-visible` ring using the primary color at low opacity, meeting keyboard-nav accessibility.
- **Inputs** — `.input-field`, `.input-label`, `.input-hint`, `.input-error` (the current `initInputFeedback()` blur-validation JS hook must keep working — same class toggling contract). Include select/dropdown, date picker, and file upload styling since the app uses all three (profile photo upload, note images, lab report uploads).
- **Cards** — `.card`, `.card-elevated`, `.card-interactive` (hover-lift used for clickable patient rows / dashboard tiles).
- **Badges** — full status/role set listed in §1, each semantically colored (role badges use the primary/secondary palette, status badges use semantic colors: pending=amber, approved/completed/verified=green, denied/expired=red, cancelled=slate, scheduled=blue, encrypted=a distinct "security" treatment — e.g., blue with a small lock glyph — since this badge is your key trust signal throughout the app).
- **Tables** (`.data-table`) — sticky header, comfortable row height, zebra or hover-row highlight (subtle), right-aligned numeric/date columns, status column using badges, clear empty state, must remain compatible with `[data-href]` clickable-row JS.
- **Stat cards / stat bars** (dashboard KPIs) — `.stat-card`, `.stat-card-header`, `.stat-card-value`, `.stat-card-label`, plus accent variants — redesign as clean metric tiles (think Stripe dashboard), not the current colored-glow treatment.
- **Sidebar** (`partials/sidebar.html`) — light surface, clear active-state (filled pill or left-border accent in primary blue, not glow), role badge at top, section labels in uppercase caption style, sign-out anchored at bottom. Preserve the exact role-conditional structure (patient/doctor/admin blocks) and every `href`.
- **Topbar** (`partials/topbar.html`) — currently minimal (442 bytes); flesh out into a clean top bar with page title context and room for the security/encryption trust indicator (e.g., a persistent small "End-to-end encrypted" badge) without adding new backend calls.
- **Alerts / flash messages** (`.alert-success/error/warning/info`) — tinted background + left accent bar + icon, auto-dismiss behavior from `app.js` (`initFlashDismiss`) unchanged.
- **Toasts** — the inline `_showSessionExpiredToast` pattern referenced in `base.html`'s inline script currently falls back to an ad-hoc styled `<div>`; formalize this into a proper `.toast` component in `components.css` and update that fallback branch to use the new class instead of inline styles.
- **Modals / inline confirm** (`.inline-confirm`) — used for destructive actions (revoke access, delete note); redesign as a calm, clearly-worded confirmation pattern, not a jarring red popup. Preserve `data-confirm-trigger`/`data-confirm-cancel` contract.
- **Tabs** (`.tabs`, `.tab-item`, `.tab-count`) — used for `data-tab-group` sections and the auth role switcher; underline or pill style, active state in primary blue.
- **Empty states** (`.empty-state`) — every list/table view (access requests, notes, prescriptions, lab reports, appointments) needs a warm, encouraging empty state per §5 copy rules, with an icon and a primary action where relevant (e.g., "Invite your doctor to request access" rather than a bare "No data").
- **Skeleton loaders / spinners** — replace shimmer colors for light backgrounds; use skeletons (not just spinners) for table/card content wherever the app fetches data client-side via `fetchWithAuth`.
- **Auth shell** (`.auth-shell`, `.auth-left/.auth-right`, `.auth-form`, `.auth-tab-switcher`, `.auth-trust-list`) — this is the first impression of the product. Left panel: brand story + trust signals (encryption, patient ownership, zero-trust access) with a tasteful, restrained visual replacing the current neon "vault" graphic (`.vault-visual`/`.vault-core`/`.vault-ring-*`) — reinterpret it in the new palette as a subtle, professional security motif (e.g., a soft concentric-ring or shield illustration in blues, not glowing purple/gold). Right panel: the actual login/register form with role tabs.
- **Landing page** (`landing.html`, `.hero`, `.how-step`, `.arch-diagram`, `.cta-section`, `.landing-nav`, `.landing-footer`) — redesign as a calm marketing page: clear hero headline/subhead, "how it works" steps, a simplified architecture diagram in the new palette, trust/security proof points, CTA section, footer with legal links.
- **Notes component** (`.note-card`, `.note-form`, `.note-footer`) — used for doctor clinical notes shown to patients; should read like a clean clinical timeline entry, not a generic card.
- **Filter bar** (`.filter-bar`, `.filter-select`) — used above tables/lists (audit log, appointments, prescriptions); align with the new input styling.

---

## 5. CONTENT / MICROCOPY REWRITE

Audit every user-facing string currently rendered in the templates and Flask `flash()` calls in `landing.py`, `patient_portal.py`, and `doctor_portal.py`, and rewrite technical/robotic strings into warm, human, reassuring language, while keeping meaning and any dynamic values (names, doctor names, dates) intact. Apply this pattern consistently:

- Success confirmations should reassure and state what actually happened in plain language (e.g., a save confirmation should name what was saved, an access-grant confirmation should name who now has access, an encryption-related confirmation should reassure the data is protected — without inventing details not present in the original message).
- Error messages should explain what went wrong and what the user can do next, not surface raw error codes or backend jargon (e.g., `password_reset_required` / `invalid_or_expired_token` style strings must never reach the UI verbatim — map every backend error code to a friendly sentence).
- Empty states should encourage the relevant next action (e.g., no access requests yet → explain how a doctor requests access; no prescriptions yet → explain they'll appear here after a visit).
- Loading states should say what's happening in a small, calm way (e.g., "Loading your health record…" not a bare spinner with no label).
- Keep tone: professional, warm, confident — never cutesy, never alarmist (this is health data; avoid gamification language, exclamation-mark overuse, or jokes).

Deliverable requirement: produce an explicit **before → after copy table** for every string you change, grouped by template/file, so it can be reviewed before being applied.

---

## 6. PAGE-BY-PAGE REQUIREMENTS

For each page, apply the new design system and additionally address the specifics below. Preserve every existing data field, table column, form field, and action currently present — this is a restyle/restructure, not a feature cut.

- **Landing (`landing.html`)** — hero, problem/solution framing, how-it-works steps, architecture visual, trust/security section, auth entry.
- **Auth (embedded in landing)** — role-tabbed login/register, OTP flow states, clear password requirements/strength feedback, "forgot password"/legacy-account-upgrade path (`/login/upgrade`) explained in plain language.
- **Dashboard (`dashboard.html`, largest template at 38KB)** — role-aware: patient sees health summary/quick actions/recent activity/upcoming appointments; doctor sees patient queue/pending requests/today's schedule; admin sees operational overview. Use the new `.stat-card` grid + recent-activity list + quick-actions cluster pattern. This is the highest-visibility screen — treat it as the flagship of the redesign.
- **Health Record (`health_record.html`, 49KB — largest template)** — this is the core patient data view (vitals, history, lifestyle, address/metadata). Needs the strongest information-hierarchy work: group into clearly labeled sections/cards, use `.field-label`/`.field-value` pairs consistently, add clear section anchors/tabs for long content.
- **EMR (`emr.html`)** — clinical profile view; align styling with Health Record but keep its distinct scope (allergies, conditions, encounters) visually legible via badges/tags.
- **Encounter Detail (`encounter_detail.html`)** — timeline-style detail page for a single encounter.
- **Prescriptions / Doctor Prescriptions** — table + detail pattern, drug/dosage/frequency/duration displayed clearly, allergy-conflict warning (F1 feature from `CHANGES.md`) styled as a clear, non-alarming warning callout, not a jarring red block.
- **Lab Reports / Doctor Lab Reports** — table + upload flow, file type/size guidance shown inline near the upload control.
- **Notes / Doctor Notes** — patient-facing read view uses `.note-card` timeline; doctor-facing "add note" form should feel like a fast, low-friction clinical input tool.
- **Access Requests (`access_requests.html`)** — the trust-critical screen: pending/approved/denied list, clear approve/deny actions, and a clear explanation of what granting access means (duration, scope) before the patient confirms.
- **Audit Log (`audit_log.html`)** — filterable, sortable table of security events; this page should visually reinforce transparency/trust (clean, legible, exportable-feeling), not look like a raw log dump.
- **Appointments (`appointments.html`)** — request/list/respond flows for both patient and doctor.
- **My Patients / Patient Detail (doctor-side)** — patient roster table → detail view with tabs for record/notes/prescriptions/lab reports, matching the tab pattern defined in §4.
- **Profile & Settings (`profile.html`)** — account info, password/security settings, profile photo upload — group into clear sections (Personal Info / Security / Preferences).

---

## 7. RESPONSIVENESS & ACCESSIBILITY

- Full support across desktop, laptop, tablet, and mobile. The sidebar (`.page-shell`/`.page-main`, fixed 240px) must collapse to an off-canvas or bottom-nav pattern below a defined breakpoint (e.g., 960px) — specify the exact mechanism and update `app.js` only as needed to toggle it.
- All grids (`.grid-2/3/4`, `.grid-sidebar`) need explicit responsive collapse rules (e.g., to single-column below 768px).
- Tables need a defined small-screen strategy (horizontal scroll with visible affordance, or a stacked-card fallback) — pick one and apply it consistently.
- WCAG AA minimum: color contrast, visible `:focus-visible` states on every interactive element, semantic HTML (proper heading order, `<label for>` associations, `aria-current` on active nav item, `role="alert"` preserved on flash messages as already present, `aria-hidden` preserved on decorative icons as already present).
- Respect `prefers-reduced-motion` by disabling non-essential transitions/animations for users who request it.

---

## 8. DELIVERABLE FORMAT FOR THE EXECUTING SESSION

When you (the executing Claude session) do this work, produce it in this order so it can be reviewed incrementally:

1. **New token system** — full rewritten `:root` block for `base.css` with every variable named and commented, plus a short rationale for each color choice (contrast ratios for text-on-surface pairs).
2. **Component library pass** — rewritten `components.css`, organized by component, preserving every existing class name used by templates/JS (add new classes only where a genuinely new component is needed, e.g., `.toast`).
3. **Copy table** — the before/after microcopy audit from §5.
4. **Template-by-template diff plan** — for each `.html` file, a list of structural changes (what markup is being restructured, what inline styles are being removed and replaced with classes) before actually editing, so scope is visible.
5. **Execution** — apply the changes file by file, running/checking the app after each major template to confirm no broken Jinja syntax or missing static assets.
6. **Final self-audit** — confirm: every route still renders, every `data-*` JS hook still has a matching element, every form field name/id is unchanged, no backend file was modified, contrast-checked color pairs, and a responsive check at 375px/768px/1440px widths.

Do not skip ahead to execution before presenting the token system and component plan for confirmation, unless explicitly told to proceed straight to execution.
