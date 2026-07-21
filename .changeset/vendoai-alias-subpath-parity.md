---
"vendoai": minor
---

The `vendoai` alias now mirrors the full `@vendoai/vendo` export surface: the
`./extract`, `./ai-sdk`, and `./mastra` subpaths were missing. The alias test
now pins exports-map parity so a subpath added to `@vendoai/vendo` without a
mirror fails the suite instead of drifting silently.
