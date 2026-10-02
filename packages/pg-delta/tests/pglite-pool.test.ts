/**
 * extract() over the minimal Pool contract the README documents ("Bring your own
 * Pool"), driven by an in-process PGlite through the reference adapter in
 * ./pglite-pool.ts. Two upstream breaks motivated it: checking clients out with
 * the callback `pool.connect(cb)`, and sending multi-statement batches inside the
 * extraction transaction. Both hung or aborted extraction for PGlite consumers.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PGlite } from "@electric-sql/pglite";
import { extract } from "../src/extract/extract.ts";
import { encodeId } from "../src/core/stable-id.ts";
import type { FactBase } from "../src/core/fact.ts";
import { createTestDb, type TestDb } from "./containers.ts";
import { pglitePool } from "./pglite-pool.ts";

const SCHEMA = `
CREATE SCHEMA app;
CREATE TYPE app.mood AS ENUM ('sad', 'ok', 'happy');
CREATE TABLE app.users (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL,
  mood app.mood DEFAULT 'ok',
  tags text[] DEFAULT '{}',
  created timestamptz DEFAULT now()
);
CREATE INDEX users_name_idx ON app.users (lower(name));
CREATE VIEW app.names AS SELECT id, name FROM app.users;
CREATE FUNCTION app.hello(n int) RETURNS int LANGUAGE sql IMMUTABLE AS $$ SELECT n + 1 $$;
COMMENT ON TABLE app.users IS 'people';
`;

// PGlite embeds PostgreSQL 17.
const PGLITE_MAJOR = 17;

const users = { kind: "table", schema: "app", name: "users" } as const;

/** Per-fact content hashes, minus roles: cluster-level role attributes differ
 *  between an embedded PGlite and a container by construction. */
function objectHashes(factBase: FactBase): Map<string, string> {
  return new Map(
    factBase
      .facts()
      .filter((fact) => fact.id.kind !== "role")
      .map((fact) => [encodeId(fact.id), factBase.hashOf(fact.id)]),
  );
}

describe("extract() through a PGlite pool", () => {
  let lite: PGlite;

  beforeAll(async () => {
    lite = new PGlite();
    // Own the objects as `test`, the role the test cluster creates them as.
    await lite.exec(
      "CREATE ROLE test; GRANT CREATE ON DATABASE postgres TO test; SET ROLE test",
    );
    await lite.exec(SCHEMA);
    await lite.exec("RESET ROLE");
  });

  afterAll(async () => {
    await lite.close();
  });

  test("completes and sees the schema", async () => {
    const { factBase } = await extract(pglitePool(lite));
    expect(factBase.has(users)).toBe(true);
  }, 60_000);

  test("stays serial on a max-1 pool even when concurrency is requested", async () => {
    const { factBase } = await extract(pglitePool(lite), { concurrency: 4 });
    expect(factBase.has(users)).toBe(true);
  }, 60_000);

  describe("against a real PostgreSQL of the same major", () => {
    let db: TestDb;
    let major: number;

    beforeAll(async () => {
      db = await createTestDb("pglite_pool");
      const { rows } = await db.pool.query<{ num: number }>(
        "SELECT current_setting('server_version_num')::int AS num",
      );
      major = Math.floor((rows[0]?.num ?? 0) / 10_000);
      await db.pool.query(SCHEMA);
    }, 120_000);

    test("every schema-object fact hashes identically", async () => {
      // Catalog output differs across majors (e.g. MAINTAIN on 17+), so the
      // byte-for-byte comparison is only meaningful on the major PGlite embeds.
      if (major !== PGLITE_MAJOR) return;
      const fromLite = objectHashes((await extract(pglitePool(lite))).factBase);
      const fromPg = objectHashes((await extract(db.pool)).factBase);
      expect(fromLite.size).toBeGreaterThan(0);
      expect(Object.fromEntries(fromLite)).toEqual(Object.fromEntries(fromPg));
    }, 120_000);
  });
});
