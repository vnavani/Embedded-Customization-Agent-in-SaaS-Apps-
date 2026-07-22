---
"@vendoai/ui": minor
---

White-label sweep: end-user chrome copy no longer names the product. The
whisper caption is configurable via a new `VendoOverlay` `whisper` prop
(`{ title, caption }`) with neutral defaults; the overlay dialog, close
button, trigger default label, approval-card copy, and chrome aria-labels
all use neutral "AI"/"agent" wording. Host-supplied copy is unaffected.
