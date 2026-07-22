# White-label sweep — browser-verified evidence (2026-07-22)

Captured off the ui e2e harness (`/overlay-manual` scenario, real Chromium via
Playwright) for the white-label sweep in this lane (PR #1).

- `evidence-whisper-neutral.png` — the fire-once whisper with the neutral
  default caption ("Ask the agent to build the view you need.") beside the
  white-label "AI agent" launcher pill.
- `evidence-overlay-dialog.png` — the opened overlay: dialog labeled
  "AI assistant", "Close assistant" control, neutral greeting; no product
  name anywhere in end-user copy.

Both states were also asserted in-browser (Playwright locators on the new
aria-labels and caption text) before capture.
