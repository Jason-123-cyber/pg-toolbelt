/**
 * Applier-capability-restricted view (docs/architecture/managed-view-architecture.md move 6).
 *
 * The managed view is a function of (facts, policy, applier capability). An
 * operation the applier cannot execute is projected out — FDW ACLs (superuser
 * GRANT/REVOKE) and PG16+ CREATEROLE self-ADMIN memberships (0LP01). With no
 * capability (or a superuser), the view is unrestricted — the corpus path is
 * unchanged.
 */
import { describe, expect, test } from "bun:test";
import { buildFactBase, type Fact } from "../core/fact.ts";
import { encodeId, type StableId } from "../core/stable-id.ts";
import type { Pool } from "pg";
import { apply } from "../apply/apply.ts";
import { provePlan } from "../proof/prove.ts";
import { resolveView } from "./policy.ts";
import { plan } from "../plan/plan.ts";
import {
  CAPABILITY_CREATEROLE_SELF_ADMIN,
  CAPABILITY_FDW_ACL,
  CAPABILITY_OWNER,
  capabilityExcludedRoots,
  type ApplierCapability,
} from "./capability.ts";

const f = (id: StableId): Fact => ({ id, payload: {} });
const fdw: StableId = { kind: "fdw", name: "w" };
const fdwAcl: StableId = { kind: "acl", target: fdw, grantee: "u" };
const tbl: StableId = { kind: "table", schema: "public", name: "t" };
const tblAcl: StableId = { kind: "acl", target: tbl, grantee: "u" };

const superuser: ApplierCapability = {
  role: "postgres",
  isSuperuser: true,
  memberOf: [],
};
const nonSuper: ApplierCapability = {
  role: "app",
  isSuperuser: false,
  memberOf: [],
};

describe("ApplierCapability — capability-restricted view (move 6)", () => {
  test("non-superuser → FDW ACL projected out of the view; table ACL kept", () => {
    const fb = buildFactBase([f(fdw), f(fdwAcl), f(tbl), f(tblAcl)], []);
    const view = resolveView(fb, undefined, nonSuper);
    expect(view.get(fdwAcl)).toBeUndefined(); // GRANT/REVOKE on FDW needs superuser
    expect(view.get(tblAcl)).toBeDefined(); // table ACLs are fine
    expect(view.get(fdw)).toBeDefined(); // the FDW object stays — only its ACL is unappliable
  });

  test("superuser → unrestricted view", () => {
    const fb = buildFactBase([f(fdw), f(fdwAcl)], []);
    expect(resolveView(fb, undefined, superuser).get(fdwAcl)).toBeDefined();
  });

  test("no capability → unrestricted view (corpus path)", () => {
    const fb = buildFactBase([f(fdw), f(fdwAcl)], []);
    expect(resolveView(fb, undefined, undefined).get(fdwAcl)).toBeDefined();
  });

  test("capabilityExcludedRoots: empty for superuser, the FDW ACL for non-superuser", () => {
    const fb = buildFactBase([f(fdw), f(fdwAcl), f(tbl), f(tblAcl)], []);
    expect(capabilityExcludedRoots(fb, superuser).size).toBe(0);
    const roots = capabilityExcludedRoots(fb, nonSuper);
    expect(roots.size).toBe(1);
    expect(roots.get(encodeId(fdwAcl))).toBe(CAPABILITY_FDW_ACL);
  });
});

describe("ApplierCapability — PG16+ CREATEROLE self-ADMIN membership", () => {
  const created: StableId = { kind: "role", name: "created" };
  const parent: StableId = { kind: "role", name: "parent" };
  const child: StableId = { kind: "role", name: "child" };
  const selfAdmin: StableId = {
    kind: "membership",
    role: "created",
    member: "app",
  };
  const peerGrant: StableId = {
    kind: "membership",
    role: "parent",
    member: "child",
  };
  const selfPlain: StableId = {
    kind: "membership",
    role: "created",
    member: "app",
  };
  const createrolePg16: ApplierCapability = {
    role: "app",
    isSuperuser: false,
    memberOf: [],
    createRole: true,
    pgMajor: 16,
  };
  const membershipFb = () =>
    buildFactBase(
      [
        f(created),
        f(parent),
        f(child),
        { id: selfAdmin, payload: { admin: true } },
        { id: peerGrant, payload: { admin: false } },
      ],
      [],
    );

  test("excludes admin self-membership for a PG16+ CREATEROLE non-superuser", () => {
    const fb = membershipFb();
    const roots = capabilityExcludedRoots(fb, createrolePg16);
    expect(roots.get(encodeId(selfAdmin))).toBe(
      CAPABILITY_CREATEROLE_SELF_ADMIN,
    );
    expect(roots.has(encodeId(peerGrant))).toBe(false);
    expect(
      resolveView(fb, undefined, createrolePg16).get(selfAdmin),
    ).toBeUndefined();
    expect(
      resolveView(fb, undefined, createrolePg16).get(peerGrant),
    ).toBeDefined();
  });

  test("keeps a non-admin self-membership", () => {
    const fb = buildFactBase(
      [f(created), { id: selfPlain, payload: { admin: false } }],
      [],
    );
    expect(capabilityExcludedRoots(fb, createrolePg16).size).toBe(0);
  });

  test("superuser, PG < 16, or omitted probe fields do not exclude", () => {
    const fb = membershipFb();
    expect(capabilityExcludedRoots(fb, superuser).size).toBe(0);
    expect(
      capabilityExcludedRoots(fb, {
        ...createrolePg16,
        pgMajor: 15,
      }).size,
    ).toBe(0);
    expect(
      capabilityExcludedRoots(fb, {
        role: "app",
        isSuperuser: false,
        memberOf: [],
      }).size,
    ).toBe(0);
    expect(
      capabilityExcludedRoots(fb, {
        ...createrolePg16,
        createRole: false,
      }).size,
    ).toBe(0);
  });
});

describe("ApplierCapability — owner residue (follow-up 1)", () => {
  // owner can't be silently skipped (acldefault is owner-relative → no
  // convergence). plan() still emits the owner ALTER and flags it; apply()
  // refuses the flagged plan before any statement runs.
  const schemaApp: StableId = { kind: "schema", name: "app" };
  const r1: StableId = { kind: "role", name: "r1" };
  const r2: StableId = { kind: "role", name: "r2" };
  const memberOfR1: ApplierCapability = {
    role: "app",
    isSuperuser: false,
    memberOf: ["r1"],
  };
  const ownerEdge = (to: StableId) =>
    ({ from: schemaApp, to, kind: "owner" }) as const;
  const desiredOwnedBy = (role: StableId) =>
    buildFactBase([f(schemaApp), f(role)], [ownerEdge(role)]);
  const source = (role: StableId) => buildFactBase([f(role)], []);
  const untouchablePool = new Proxy(
    {},
    {
      get() {
        throw new Error("apply touched the target pool");
      },
    },
  ) as unknown as Pool;

  test("plan emits the owner ALTER with a warning when the applier cannot set the owner", () => {
    const thePlan = plan(source(r2), desiredOwnedBy(r2), {
      capability: memberOfR1,
    });
    expect(thePlan.actions.some((a) => a.sql.includes('OWNER TO "r2"'))).toBe(
      true,
    );
    expect(thePlan.diagnostics).toEqual([
      {
        code: CAPABILITY_OWNER,
        severity: "warning",
        subject: schemaApp,
        message: expect.stringMatching(
          /cannot set owner of schema:app to role "r2" — applier "app"/,
        ),
        context: { role: "r2", applier: "app" },
      },
    ]);
  });

  test("apply refuses a flagged plan before touching the target", async () => {
    const thePlan = plan(source(r2), desiredOwnedBy(r2), {
      capability: memberOfR1,
    });
    const err = await apply(thePlan, untouchablePool).catch((e: unknown) => e);
    expect(String(err)).toMatch(
      /apply: cannot set owner of schema:app to role "r2"/,
    );
  });

  test("prove refuses a flagged plan before any clone work", async () => {
    const thePlan = plan(source(r2), desiredOwnedBy(r2), {
      capability: memberOfR1,
    });
    const err = await provePlan(thePlan, untouchablePool, desiredOwnedBy(r2), {
      reextract: () => {
        throw new Error("prove re-extracted the clone");
      },
    }).catch((e: unknown) => e);
    expect(String(err)).toMatch(
      /prove: cannot set owner of schema:app to role "r2"/,
    );
  });

  test("stripping the owner warning invalidates the planId", async () => {
    const { diagnostics: _dropped, ...stripped } = plan(
      source(r2),
      desiredOwnedBy(r2),
      { capability: memberOfR1 },
    );
    const err = await apply(stripped, untouchablePool).catch((e: unknown) => e);
    expect(String(err)).toMatch(/apply: planId does not match contents/);
  });

  test("no warning when the owner is a role the applier is a member of", () => {
    const thePlan = plan(source(r1), desiredOwnedBy(r1), {
      capability: memberOfR1,
    });
    expect(thePlan.diagnostics).toBeUndefined();
  });

  test("superuser can set any owner (no warning)", () => {
    const thePlan = plan(source(r2), desiredOwnedBy(r2), {
      capability: superuser,
    });
    expect(thePlan.diagnostics).toBeUndefined();
  });

  test("no capability → no owner restriction (corpus path)", () => {
    expect(plan(source(r2), desiredOwnedBy(r2)).diagnostics).toBeUndefined();
  });
});

describe("ApplierCapability — owner ALTER the applier can make runnable", () => {
  const schemaApp: StableId = { kind: "schema", name: "app" };
  const r2: StableId = { kind: "role", name: "r2" };
  const selfGrant: StableId = { kind: "membership", role: "r2", member: "app" };
  const creator = (
    pgMajor: number,
    extra: Partial<ApplierCapability> = {},
  ): ApplierCapability => ({
    role: "app",
    isSuperuser: false,
    memberOf: [],
    createRole: true,
    pgMajor,
    adminOf: [],
    ...extra,
  });
  const roleFact: Fact = { id: r2, payload: {} };
  const desired = (extra: Fact[] = []) =>
    buildFactBase(
      [f(schemaApp), roleFact, ...extra],
      [{ from: schemaApp, to: r2, kind: "owner" }],
    );
  const alter = 'ALTER SCHEMA "app" OWNER TO "r2"';
  const wrappedSequence = [
    'GRANT "r2" TO "app"',
    alter,
    'REVOKE "r2" FROM "app"',
  ];
  const sqls = (p: ReturnType<typeof plan>) => p.actions.map((a) => a.sql);
  const expectWrapped = (p: ReturnType<typeof plan>) => {
    const all = sqls(p);
    const at = wrappedSequence.map((sql) => all.indexOf(sql));
    expect(at.every((i) => i >= 0)).toBe(true);
    expect([...at].sort((x, y) => x - y)).toEqual(at);
    expect(p.diagnostics).toBeUndefined();
  };

  test("PG16+: owner role created by the plan → grant, alter, revoke", () => {
    expectWrapped(
      plan(buildFactBase([], []), desired(), { capability: creator(17) }),
    );
  });

  test("PG16+: createrole_self_grant with SET already lets the creator own", () => {
    const p = plan(buildFactBase([], []), desired(), {
      capability: creator(17, { createroleSelfGrant: "set, inherit" }),
    });
    expect(sqls(p)).toContain(alter);
    expect(sqls(p).some((sql) => sql.startsWith('GRANT "r2"'))).toBe(false);
    expect(p.diagnostics).toBeUndefined();
  });

  test("PG16+: createrole_self_grant without SET stays flagged (REVOKE would drop it)", () => {
    const p = plan(buildFactBase([], []), desired(), {
      capability: creator(17, { createroleSelfGrant: "inherit" }),
    });
    expect(p.diagnostics?.map((d) => d.code)).toEqual([CAPABILITY_OWNER]);
  });

  test("an existing role the probe reports as grantable → grant, alter, revoke", () => {
    expectWrapped(
      plan(buildFactBase([roleFact], []), desired(), {
        capability: creator(17, { adminOf: ["r2"] }),
      }),
    );
  });

  test("ADMIN OPTION alone is enough, without CREATEROLE", () => {
    expectWrapped(
      plan(buildFactBase([roleFact], []), desired(), {
        capability: creator(17, { createRole: false, adminOf: ["r2"] }),
      }),
    );
  });

  test("an existing role the probe does not report stays flagged", () => {
    const p = plan(buildFactBase([roleFact], []), desired(), {
      capability: creator(15),
    });
    expect(sqls(p)).toContain(alter);
    expect(p.diagnostics?.map((d) => d.code)).toEqual([CAPABILITY_OWNER]);
  });

  test("an object ALTER orders after its schema's ALTER to the same role", () => {
    const tbl: StableId = { kind: "table", schema: "app", name: "t" };
    const p = plan(
      buildFactBase([], []),
      buildFactBase(
        [
          f(schemaApp),
          roleFact,
          {
            id: tbl,
            payload: {
              persistence: "p",
              rowSecurity: false,
              forceRowSecurity: false,
              replicaIdentity: "d",
              replicaIdentityIndex: null,
              partitionKey: null,
              partitionBound: null,
              parentTable: null,
            },
          },
        ],
        [
          { from: schemaApp, to: r2, kind: "owner" },
          { from: tbl, to: r2, kind: "owner" },
        ],
      ),
      { capability: creator(17), compact: false },
    );
    const all = sqls(p);
    const schemaAlter = all.indexOf(alter);
    const tableAlter = all.findIndex((sql) =>
      sql.startsWith('ALTER TABLE "app"."t" OWNER TO'),
    );
    expect(schemaAlter).toBeGreaterThanOrEqual(0);
    expect(tableAlter).toBeGreaterThan(schemaAlter);
  });

  test("several objects owned by one wrapped role share one GRANT and one REVOKE", () => {
    const tbl: StableId = { kind: "table", schema: "app", name: "t" };
    const p = plan(
      buildFactBase([], []),
      buildFactBase(
        [
          f(schemaApp),
          roleFact,
          {
            id: tbl,
            payload: {
              persistence: "p",
              rowSecurity: false,
              forceRowSecurity: false,
              replicaIdentity: "d",
              replicaIdentityIndex: null,
              partitionKey: null,
              partitionBound: null,
              parentTable: null,
            },
          },
        ],
        [
          { from: schemaApp, to: r2, kind: "owner" },
          { from: tbl, to: r2, kind: "owner" },
        ],
      ),
      { capability: creator(17) },
    );
    const all = sqls(p);
    const grants = all.flatMap((sql, i) =>
      sql === 'GRANT "r2" TO "app"' ? [i] : [],
    );
    const revokes = all.flatMap((sql, i) =>
      sql === 'REVOKE "r2" FROM "app"' ? [i] : [],
    );
    const alters = all.flatMap((sql, i) =>
      sql.endsWith(' OWNER TO "r2"') ? [i] : [],
    );
    expect(grants).toHaveLength(1);
    expect(revokes).toHaveLength(1);
    expect(alters).toHaveLength(2);
    for (const a of alters) {
      expect(a).toBeGreaterThan(grants[0] as number);
      expect(a).toBeLessThan(revokes[0] as number);
    }
  });

  describe("owner change of an existing object also needs the current owner", () => {
    const r1: Fact = { id: { kind: "role", name: "r1" }, payload: {} };
    const ownedByR1 = buildFactBase(
      [f(schemaApp), r1],
      [{ from: schemaApp, to: r1.id, kind: "owner" }],
    );
    const ownedByR2 = (withR2: boolean) =>
      buildFactBase(
        [f(schemaApp), r1, ...(withR2 ? [roleFact] : [])],
        [{ from: schemaApp, to: r2, kind: "owner" }],
      );

    test("flagged, not wrapped, when the applier cannot act as the current owner", () => {
      const p = plan(ownedByR1, ownedByR2(true), {
        capability: creator(17, { usageOf: [] }),
      });
      expect(sqls(p).some((sql) => sql.startsWith('GRANT "r2"'))).toBe(false);
      expect(p.diagnostics?.map((d) => d.code)).toEqual([CAPABILITY_OWNER]);
    });

    test("flagged even when the new owner is directly settable", () => {
      const p = plan(
        buildFactBase(
          [f(schemaApp), r1, roleFact],
          [{ from: schemaApp, to: r1.id, kind: "owner" }],
        ),
        ownedByR2(true),
        { capability: creator(17, { memberOf: ["r2"], usageOf: [] }) },
      );
      expect(p.diagnostics?.map((d) => d.code)).toEqual([CAPABILITY_OWNER]);
    });

    test("a planned GRANT current-owner TO applier counts, ordered before the ALTER", () => {
      const app: Fact = { id: { kind: "role", name: "app" }, payload: {} };
      const viaR1: StableId = {
        kind: "membership",
        role: "r1",
        member: "app",
      };
      const p = plan(
        buildFactBase(
          [f(schemaApp), r1, roleFact, app],
          [{ from: schemaApp, to: r1.id, kind: "owner" }],
        ),
        buildFactBase(
          [
            f(schemaApp),
            r1,
            roleFact,
            app,
            { id: viaR1, payload: { admin: false } },
          ],
          [{ from: schemaApp, to: r2, kind: "owner" }],
        ),
        { capability: creator(17, { memberOf: ["r2"], usageOf: [] }) },
      );
      const grant = sqls(p).indexOf('GRANT "r1" TO "app"');
      const alterAt = sqls(p).indexOf(alter);
      expect(p.diagnostics).toBeUndefined();
      expect(grant).toBeGreaterThanOrEqual(0);
      expect(alterAt).toBeGreaterThan(grant);
    });

    test("not flagged when the applier has the current owner's privileges", () => {
      const p = plan(
        buildFactBase(
          [f(schemaApp), r1, roleFact],
          [{ from: schemaApp, to: r1.id, kind: "owner" }],
        ),
        ownedByR2(true),
        { capability: creator(17, { memberOf: ["r2"], usageOf: ["r1"] }) },
      );
      expect(sqls(p)).toContain(alter);
      expect(p.diagnostics).toBeUndefined();
    });
  });

  test("a planned GRANT r TO applier orders the plain ALTER after it", () => {
    const app: Fact = { id: { kind: "role", name: "app" }, payload: {} };
    const p = plan(
      buildFactBase([app], []),
      desired([app, { id: selfGrant, payload: { admin: false } }]),
      { capability: { role: "app", isSuperuser: false, memberOf: [] } },
    );
    const grant = p.actions.findIndex((a) => a.sql === 'GRANT "r2" TO "app"');
    const alterAt = p.actions.findIndex((a) => a.sql === alter);
    expect(grant).toBeGreaterThanOrEqual(0);
    expect(alterAt).toBeGreaterThan(grant);
    expect(p.actions[alterAt]?.consumes).toContainEqual(selfGrant);
    expect(p.diagnostics).toBeUndefined();
  });
});
