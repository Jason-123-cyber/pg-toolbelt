---
"@supabase/pg-delta": patch
---

Plans for a non-superuser applier now make `ALTER … OWNER TO r` runnable when they can: the owner ALTER is ordered after a planned `GRANT r TO <applier>`, after a planned CREATE grant to `r` on the object's schema, and after that schema's own owner ALTER to `r`. When the applier may grant `r` to itself — a role it creates in the plan, or one it holds ADMIN OPTION on (before PG16: any non-superuser role with CREATEROLE) — the plan emits `GRANT r TO <applier>`, the ALTER, then `REVOKE r FROM <applier>`. `probeApplierCapability` now counts only SET-able roles on PG16+, and reports `adminOf` and `createroleSelfGrant`; a created role that already self-grants SET needs no wrapper. Owners the applier still cannot set keep the `capability.owner` warning.
