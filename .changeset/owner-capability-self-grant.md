---
"@supabase/pg-delta": patch
---

Plans for a non-superuser applier now make `ALTER … OWNER TO r` runnable when they can: the owner ALTER is ordered after a planned `GRANT r TO <applier>` and after a planned CREATE grant on the object's schema, and a CREATEROLE applier that may grant `r` to itself (PG16+: ADMIN on `r`, e.g. a role the plan creates; before PG16: any non-superuser role) gets `GRANT r TO <applier>; ALTER … OWNER TO r; REVOKE r FROM <applier>` as one action. `probeApplierCapability` now counts only SET-able roles on PG16+ (an ADMIN-only grant is not enough to own objects) and reports `adminOf`. Owners the applier still cannot set keep the `capability.owner` warning.
