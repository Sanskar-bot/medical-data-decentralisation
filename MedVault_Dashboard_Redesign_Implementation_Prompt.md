# MedVault — Patient Dashboard Redesign — Implementation Prompt

> **How to use this file:** Paste this entire document as the first message to a new Claude session with access to the MedVault codebase. It is self-contained: it describes the current dashboard exactly as it exists today (verified against both a live screenshot and the actual template/JS source), and specifies the target redesign in full detail. Execute in the order given at the end. Do not summarize or skip sections.

---

## 0. SCOPE

This prompt covers **one screen only: `/dashboard`**, rendered by `portals/templates/dashboard.html`, for all three roles it serves (`patient`, `doctor`, `admin`/receptionist). It does not cover other pages (health record, EMR, prescriptions, etc.) — those are separate efforts. Do not let this redesign leak styling changes into shared files (`base.css`, `components.css`, `sidebar.html`, `topbar.html`) beyond what's explicitly specified in §9, since those are used by every other page in the app.

---

## 1. GROUND TRUTH — WHAT EXISTS TODAY

A screenshot of the live patient dashboard was analyzed alongside the actual `dashboard.html` template and its inline `<script>` block. Here is the verified current state:

### 1.1 Current layout (patient view, as seen in the screenshot)

- **Topbar:** page title "Dashboard" (left), and on the right a static `"🔒 End-to-end encrypted"` pill, the user's email, and a "Sign out" link. Generous, slightly under-used horizontal space.
- **Sidebar:** logo block ("Med**VAULT**" + "Zero-Trust Health Platform" tagline), user card (name + role badge), then four grouped sections — Overview (Dashboard, Appointments), Health Records (Health Record, EMR Profile, Prescriptions, Lab Reports, Doctor Notes), Security (Access Requests, Audit Log), Account (Profile & Settings). Active item shown with a light-blue filled pill.
- **Hero row:** small uppercase eyebrow "PATIENT DASHBOARD" → large heading "Good afternoon, {first name}" → one line of muted subtext "Your health records are encrypted and secure." A "Refresh" button floats to the right of this block, visually disconnected from the text it relates to.
- **Stat card row (4 cards):** Health Record (badge "Encrypted" + caption), Active Doctor Access (big number, caption), Pending Requests (big number in orange, caption), Audit Events (a small decorative green bar with no actual number, caption "recorded events"). All four cards are visually identical in weight even though they carry very different levels of urgency/importance.
- **Two-column body:** Left column — "Access Requests" section header, a 3-way tab bar (Pending/Approved/Denied, each with a count chip), and an empty state ("No pending requests") that leaves a **very large empty vertical gap** beneath it, since nothing else fills the left column at that scroll depth. Right column — a "Quick Actions" card with three plain icon+text rows (Unlock health record, View doctor notes, Login history — no buttons, no visual weight, no descriptions), followed by an "Encryption" status card (Encrypted badge + AES-256-GCM / key storage / zero-trust facts), then **nothing** — the right column also dead-ends with empty space below it while the left column is still much taller.
- Below the fold (not in the screenshot but present in the template): three hidden panels toggled by Quick Actions (`#record-panel` for decrypting/viewing the record, `#notes-panel` for doctor notes, `#history-panel` for login history) which take over the section space when opened.

### 1.2 Verified data wiring (do not break these contracts)

Element IDs the inline JS depends on — **any redesign must keep these exact IDs (or update the JS in the same edit) or the dashboard will silently stop working**:

| Element ID | Populated by | Notes |
|---|---|---|
| `#stat-approved` | `GET /patient/requests` (filtered, non-expired approved) | count of active doctor access grants |
| `#stat-pending` | `GET /patient/requests` (filtered) | count of pending requests |
| `#tab-count-pending` / `#tab-count-approved` / `#tab-count-denied` | same fetch | tab badge counts |
| `#pending-list` / `#approved-list` / `#denied-list` | `renderRequests()` | tab panel contents, each request row has Approve/Deny (pending) or an expiry badge (approved) or a Denied badge |
| `#record-status` badge | static markup, not fetched | always shows "Encrypted" |
| `#record-panel`, `#unlock-password`, `#unlock-submit-btn`, `#record-display` | `POST /patient/record` | password-gated decrypt-and-display flow |
| `#notes-panel`, `#notes-list` | `GET /patient/notes` | doctor notes list |
| `#history-panel`, `#history-table`, `#history-body` | `GET /patient/history` | login history table |
| `#unlock-record-btn`, `#view-notes-btn`, `#view-history-btn`, `#refresh-btn` | click handlers toggle the panels above | Quick Actions |

**Important existing gap to fix, not preserve:** `#stat-audit` ("Audit Events") is rendered in the template but **is never actually populated by any fetch in the current JS** — it's a static placeholder. The screenshot's decorative green bar with no number confirms this is currently non-functional. Your redesign must either wire it to real data (see §1.3) or replace it with something that is real — never ship a fabricated number.

### 1.3 Real data sources available to power new widgets (no backend changes needed)

The backend already exposes JSON endpoints beyond what the dashboard currently calls. These can be fetched from the dashboard's existing JWT-authenticated `fetch`/`fetchWithAuth` pattern **without any backend modification**:

- `GET /audit` page has an underlying audit log data source (see `audit_log.html` / `/portal/audit-log`) — reuse this, do not invent a count.
- `/api/emr/<subpath>` (proxied through `patient_portal.py`) exposes, per the EMR API: `appointments/patient/<id>`, `prescriptions/patient/<id>`, `lab-reports/patient/<id>`, `vitals/patient/<id>`, `conditions/patient/<id>`, `encounters/patient/<id>`. These are real, existing, already-authorized endpoints — a "Latest Lab Reports," "Recent Prescriptions," or "Upcoming Appointments" dashboard widget should call these, not simulate data.
- `GET /patient/notes` (already used for the Notes panel) can also power a "Recent Medical Activity" or timeline widget.

**Hard rule:** Any widget listed in §5 that would require data the app does not currently expose anywhere (e.g., a genuine "Storage Usage" metric, a "Health Completion Score" algorithm, or a push-notification feed) must be either (a) built from the closest real proxy available with an honest label, or (b) explicitly marked in your implementation plan as **"Phase 2 — requires new backend support, not built in this pass"** with a clean, honest empty/coming-soon state. Never hardcode placeholder numbers as if they were live data — that would misrepresent a security/medical product's own trustworthiness, which directly contradicts the goal of this redesign.

### 1.4 Current visual system

Note: the live screenshot shows a clean light theme (white surfaces, blue primary accent, soft gray borders, green success accents) already in place for this dashboard — carry that theme forward and refine it per §6, rather than assuming a dark-theme starting point.

---

## 2. WHAT THIS DASHBOARD IS FOR

This is the home screen of a patient-owned, end-to-end encrypted medical records platform. It is not an admin panel, not a dev tool, not a crypto dashboard. Within five seconds of landing here, a patient should be able to answer:

1. **How secure am I right now?**
2. **What changed recently?**
3. **Do I need to do anything today?**
4. **Who currently has access to my data?**
5. **What are my recent medical updates?**
6. **What should I do next?**

Everything on the page should serve one of these six questions. If a component doesn't serve one of them, cut it or demote it.

### Design inspiration (principles, not pastiche)

Draw on the *underlying principles* of Apple Health / HIG (calm clarity, restraint, generous whitespace used purposefully), Stripe Dashboard (information-dense but never cluttered, confident typography, precise alignment), Linear (speed, keyboard-friendly, minimal chrome), Notion (flexible content blocks, friendly empty states), Mercury Bank (financial-grade trust cues applied to a different high-stakes domain — here, health data), and Google Material 3 / Microsoft Fluent (systemic elevation, motion, and accessibility discipline). Do not literally copy any of these products' chrome, logos, or signature components — synthesize the principles into something that reads as its own product.

---

## 3. THE CORE PROBLEM WITH TODAY'S LAYOUT

Name this explicitly in your implementation plan before touching code:

1. **Empty space is not intentional whitespace — it's unfinished layout.** The dead zone below "No pending requests" and below the Quick Actions/Encryption stack are the clearest symptoms. Whitespace should be a deliberate rhythm element, not leftover space because content ran out.
2. **All four stat cards carry equal visual weight** regardless of urgency (a "0 pending requests" and "AES-256-GCM encrypted" are not equally important at a glance).
3. **Quick Actions are underpowered** — three plain text rows with tiny icons, no descriptions, no visual invitation to click, when they are literally the primary calls-to-action on the page.
4. **The hero doesn't yet do its job** — it states a fact ("your records are encrypted") but doesn't yet tell the patient anything dynamic or specific to *today* (e.g., whether anything needs their attention).
5. **There is no sense of time or narrative** — nothing on the page currently shows the patient "what happened recently" as a story; it's all static current-state snapshots.
6. **The "Audit Events" stat is decorative, not real** (see §1.2) — a trust product cannot afford a fake-looking metric.

---

## 4. HERO SECTION — REDESIGN SPEC

Replace the current three-line hero with a richer but still calm greeting block:

- **Line 1 (large, primary):** Time-aware greeting + first name, exactly as today (`Good morning / afternoon / evening, {first_name}`) — keep this, it already works.
- **Line 2 (status sentence, dynamic):** A single reassuring sentence that changes based on real state pulled from the same `/patient/requests` fetch already on the page:
  - If pending requests > 0: name the count and prompt action (e.g., referencing that a specific number of doctors are waiting for a decision).
  - If pending requests = 0 and active access > 0: reassure that records are protected and name how many doctors currently have access.
  - If pending = 0 and active = 0: reassure that records are protected and no one currently has access.
  - This sentence must be derived from real fetched numbers already available client-side — do not hardcode "No new access requests today" as static copy; compute it.
- **Line 3 (optional, small, muted):** last-login or last-activity timestamp if available from `/patient/history`, to reinforce "what changed recently."
- **Placement of Refresh button:** move it to align visually with the hero block (e.g., right-aligned at the vertical center of the greeting block, not floating above it disconnected) or relocate it into the topbar as a small icon-button next to the encrypted pill, since "refresh the dashboard" is a page-level action, not specifically a hero action.
- Keep the greeting purely text-based and calm — no illustration, no large decorative graphic competing with the message.

---

## 5. WIDGET SYSTEM — WHAT FILLS THE PAGE NOW

Redesign the page as a structured widget grid instead of "4 stat cards + 2 columns." For each widget below, the data source is specified — build only what has a real source; mark anything else per the Hard Rule in §1.3.

### 5.1 Top row — Status strip (redesign of the 4 stat cards)

Keep four cards but differentiate their visual weight and richness:

1. **Security Status** (replaces "Health Record" card as the anchor tile — make this the visually dominant card of the four, e.g., spans wider or sits first with stronger color treatment): shows encrypted state, AES-256-GCM + zero-trust facts (currently duplicated in the separate Encryption card lower down — consolidate so this fact isn't stated twice on one page), a small shield/lock glyph treatment, "View security details" link that scrolls to or expands the fuller encryption panel.
2. **Doctor Access** (renames "Active Doctor Access"): big number, plus a **micro-visualization** — e.g., small stacked avatar/initials chips for the doctors currently holding active access (data already available per-row in the approved list), not just a bare number.
3. **Needs Your Attention** (renames "Pending Requests"): big number in the warning/amber accent, but now include the name(s) of the requesting doctor(s) inline or as a preview list if count > 0, and a direct "Review" button that jumps to the Access Requests panel — turn this from a passive count into an actionable card.
4. **Security Activity** (renames "Audit Events" per the humanized-copy brief, AND fixes the real-data gap from §1.2): wire this to the real audit-log data source; show an actual recent count (e.g., "past 7 days") plus a true micro-sparkline/bar if the data supports a time series, or a simple honest count with a "View audit log" link if it doesn't.

### 5.2 Main content — replace the single "Access Requests + Quick Actions" two-column layout with:

- **Access Requests panel** — keep the existing tab structure (Pending/Approved/Denied) and all existing approve/deny functionality and IDs, but give each request row a richer card treatment per §6 (doctor identity, requested date, clear primary/secondary action buttons) instead of a bare table row, and give the empty state real presence (icon + one-line reassurance + one-line explanation of how access requests work) sized to not leave a jarring void — pair it with the Medical Timeline (5.4) directly beneath it in the same column so the column height balances against the right column instead of dead-ending.
- **Quick Actions** — redesign as larger tappable cards (not text rows), 2-column grid on desktop collapsing to 1 column on mobile, each with icon + short title + one-line description. Expand the set using only actions that map to real existing routes/behaviors already in this app: Unlock Health Record (existing), View Doctor Notes (existing), Login History (existing), Manage Access → `/access-requests`, Book Appointment → `/appointments`, View Reports → `/lab-reports`. Do not invent an "Emergency Access" action unless a corresponding backend flow already exists — check before including it; if none exists, omit it rather than adding a dead button.
- **Encryption/Security details card** — keep the factual content (AES-256-GCM, device-local key storage, zero-trust) but avoid repeating it verbatim from the top-row Security Status card; make this the "expanded detail" version reached via that card's link.

### 5.3 Health snapshot widgets (new, real-data-only)

Add a "Your Health at a Glance" section using the already-existing EMR proxy endpoints (§1.3):

- **Recent Prescriptions** — small list (2–3 most recent) from `prescriptions/patient/<id>`, with a "View all" link to `/prescriptions`.
- **Latest Lab Reports** — small list from `lab-reports/patient/<id>`, link to `/lab-reports`.
- **Upcoming Appointments** — small list from `appointments/patient/<id>` filtered to future dates, link to `/appointments`.

If any of these endpoints returns empty for a given user, show a warm empty state (per §8), never a blank gap.

### 5.4 Medical Timeline (new)

A single chronological activity feed combining real events already available from existing endpoints — doctor access approvals/denials (from `/patient/requests`), new doctor notes (`/patient/notes`), and new prescriptions/lab reports/encounters if timestamps are available from the EMR proxy endpoints. Render as a vertical timeline (dot + connecting line + card per event) with relative timestamps ("2 days ago"). If cross-referencing multiple endpoints to build this is too complex for one pass, ship it scoped to whatever subset of sources you can wire cleanly first (e.g., access events + notes) rather than blocking the whole feature — note what's included vs. deferred in your plan.

---

## 6. CARD COMPONENT — RICHNESS SPEC

Every card on this page (stat cards, quick action cards, request rows, health-snapshot list items, timeline entries) should be rebuilt against one shared card pattern with:

- A meaningful icon (reuse the existing inline-SVG stroke icon set already in the app — do not introduce a new icon library for this one page).
- A short supporting description line, not just a label.
- The relevant statistic or status, sized as the visual focal point.
- A timestamp where temporally relevant.
- A status badge where relevant, using the existing `.badge-*` variants.
- A clear primary action (button or link) where the card represents something actionable.
- A defined hover state (subtle lift/shadow increase, ~150–200ms ease) for any interactive card, and no hover treatment at all for purely informational cards (don't imply interactivity that isn't there).
- Consistent internal padding and gap rhythm — pick one spacing scale and apply it to every card on this page without exception.

---

## 7. VISUAL SYSTEM FOR THIS PAGE

- **Color:** confirm/refine a light theme — white/near-white surfaces, one confident medical-blue primary, a muted slate secondary, and semantic colors (green=good/active, amber=needs attention, red=denied/expired, blue-gray=neutral/info) applied consistently across the stat cards, badges, and timeline dots. No purple, no neon, no heavy dark shadows — shadows should be soft and cool-tinted (e.g., low-opacity slate, not pure black).
- **Typography:** keep Inter; establish clear size/weight steps between the hero heading, section headers (`Access Requests`, `Quick Actions`, etc.), card titles, card values (largest numeric emphasis on the page), and supporting/caption text. No oversized or undersized text anywhere — every string must be comfortably legible at normal viewing distance.
- **Iconography:** one consistent stroke-width icon style throughout (matching what's already used in the sidebar/topbar) — audit this page for any inconsistent icon weights and fix them.
- **Motion:** subtle fade/slide-in on initial load (the existing `.fade-in` + staggered `animation-delay` pattern is good — keep and extend it to new widgets), smooth hover transitions, and if you add animated counters for the stat numbers, keep them fast (under ~600ms) and only run once on load, not on every re-render/refresh click (that would feel gimmicky on a health app where numbers can go up or down and users click Refresh often).
- Respect `prefers-reduced-motion`: disable non-essential entrance/hover animation for users who request it.

---

## 8. COPY — HUMANIZE EVERY STRING ON THIS PAGE

Produce a before → after table for every string on this screen. Apply this pattern (illustrative, not exhaustive — audit the actual template for every remaining technical label):

| Current | Direction for the rewrite |
|---|---|
| "Audit Events" | Reframe around security transparency, not raw event logging |
| "Pending Requests" / "pending your approval" | Reframe as something waiting on the patient's decision, not a queue |
| "Unlock health record" | Reframe around accessing one's own records, not a technical "unlock" action |
| "Encrypted" (bare badge) | Keep the badge short (badges need to stay compact) but let the *supporting text near it* reassure in full sentences rather than just repeating the word |
| "No pending requests" | Warm, one-line reassurance rather than a bare negative statement |
| "Loading…" / "Loading notes…" | Say specifically what's loading, in plain language |

Tone throughout: professional, warm, confident, calm — never cutesy, never alarmist, and never so casual that it undermines the seriousness of medical data. Preserve every dynamic value currently interpolated (names, dates, counts, doctor names) exactly — you're rewriting the surrounding language, not the data.

---

## 9. WHAT YOU MAY AND MAY NOT TOUCH

- You may fully rewrite `dashboard.html` (all three role branches) and its inline `<script>` block.
- You may add new CSS rules to `components.css` for genuinely new components this redesign introduces (e.g., a timeline component, richer quick-action cards) — but do not redefine existing shared classes in ways that would change how they look on other pages, unless the change is a genuine improvement that should apply app-wide (call this out explicitly and separately if you believe it's warranted, don't do it silently).
- You may add new client-side `fetch` calls to **existing** endpoints (see §1.3) to power new widgets.
- You may **not** modify anything under `server/`, `common/`, `client/`, `doctor/`, or change any API route, request/response shape, JWT/session logic, or encryption logic.
- You may **not** remove any existing route, existing button/action, or existing data currently shown (Approve/Deny actions, the record-unlock password flow, doctor notes panel, login history table) — every current capability must still be reachable, just better presented.
- If a requirement in this prompt is genuinely impossible without a backend change, stop and flag it rather than quietly faking the data or silently dropping the requirement.

---

## 10. RESPONSIVE & ACCESSIBILITY REQUIREMENTS FOR THIS PAGE

- Define explicit breakpoints for: 4-across stat row → 2×2 → single column; 2-column quick actions → single column; two-column main body (requests + sidebar widgets) → stacked single column with the Access Requests panel first, on mobile widths.
- Sidebar collapse behavior on tablet/mobile should follow whatever pattern is defined for the app shell generally — if none exists yet, propose one here and flag it as a shell-level change for confirmation rather than solving it silently inside this one page's CSS.
- Every interactive element (tabs, quick action cards, approve/deny buttons, links) needs a visible `:focus-visible` state and a minimum comfortable touch target size (~44px) on mobile.
- Color contrast: verify every text/background and icon/background pairing introduced here meets WCAG AA.
- Keep existing `role="tablist"`/`role="tab"` and `aria-label` attributes on the request tabs; extend the same semantic rigor to any new tab-like or timeline components you add.

---

## 11. DELIVERABLE ORDER

Work in this order and present each stage before moving to the next unless told to proceed straight through:

1. **Data audit** — confirm exactly which of the widgets in §5 can be built from real, already-existing endpoints today, and list any that must be deferred per the Hard Rule in §1.3.
2. **Wireframe-level layout plan** (described in text/structure, not full code) — the new grid, section order, and responsive collapse behavior, addressing every empty-space problem named in §3.
3. **Copy table** — the full before/after microcopy audit from §8.
4. **Component additions needed in `components.css`** — list new classes before writing them.
5. **Execution** — rewrite `dashboard.html` and its script block, then add only the necessary new CSS.
6. **Self-audit** — confirm every ID in the table in §1.2 still exists and is wired, every existing action still works, no fabricated data was introduced, contrast was checked, and the page was checked at 375px/768px/1440px widths.
