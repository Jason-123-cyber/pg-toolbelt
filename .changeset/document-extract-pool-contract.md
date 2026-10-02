---
"@supabase/pg-delta": patch
---

Document the minimal Pool contract `extract()` relies on (callback `connect()`, multi-statement batches over the simple protocol, `options.max` for single-connection pools), so non-node-pg pools such as PGlite adapters can target it. A PGlite-backed test now guards the contract.
