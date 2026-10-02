/**
 * A reference adapter exposing an in-process PGlite database through the minimal
 * `pg.Pool` surface `extract()` relies on (documented in the README under
 * "Bring your own Pool"). Kept deliberately small: anything pg-delta starts to
 * need beyond this contract shows up as a failure in pglite-pool.test.ts.
 */
import type { PGlite, Results } from "@electric-sql/pglite";
import type { Pool } from "pg";

type Release = (error?: Error | boolean) => void;
type ConnectCallback = (
  error: Error | undefined,
  client: PgliteClient | undefined,
  release: Release,
) => void;

interface QueryResult {
  rows: unknown[];
  fields: Results["fields"];
}

const toResult = (result: Results): QueryResult => ({
  rows: result.rows,
  fields: result.fields,
});

/**
 * node-pg semantics on top of PGlite: parameterless text goes over the simple
 * protocol (`exec`), because PGlite's `query()` rejects multi-statement text and
 * that failure aborts the open transaction. One statement returns one result,
 * several return an array, as node-pg does.
 */
async function run(
  db: PGlite,
  text: string,
  values?: readonly unknown[],
): Promise<QueryResult | QueryResult[]> {
  if (values !== undefined && values.length > 0) {
    return toResult(await db.query(text, [...values]));
  }
  const results = (await db.exec(text)).map(toResult);
  if (results.length === 1) return results[0] as QueryResult;
  return results.length === 0 ? { rows: [], fields: [] } : results;
}

class PgliteClient {
  #released = false;

  constructor(
    private readonly db: PGlite,
    private readonly onRelease: () => void,
  ) {}

  query(text: string, values?: readonly unknown[]) {
    return run(this.db, text, values);
  }

  // PGlite is in-process: there is no socket to emit connection errors.
  on(): this {
    return this;
  }

  removeListener(): this {
    return this;
  }

  release: Release = () => {
    if (this.#released) return;
    this.#released = true;
    this.onRelease();
  };
}

/** One PGlite connection, so one client at a time: `max: 1` keeps `extract()`
 *  on its serial path whatever `concurrency` asks for. */
class PglitePool {
  readonly options = { max: 1 };
  #checkedOut = false;
  readonly #waiting: (() => void)[] = [];

  constructor(private readonly db: PGlite) {}

  get totalCount(): number {
    return this.#checkedOut ? 1 : 0;
  }

  get idleCount(): number {
    return 0;
  }

  query(text: string, values?: readonly unknown[]) {
    return run(this.db, text, values);
  }

  connect(callback?: ConnectCallback): Promise<PgliteClient> | undefined {
    const checkout = this.#checkout();
    if (callback === undefined) return checkout;
    checkout.then(
      (client) => callback(undefined, client, client.release),
      (error: unknown) =>
        callback(error as Error, undefined, () => {
          /* nothing was checked out */
        }),
    );
    return undefined;
  }

  async end(): Promise<void> {
    /* the caller owns the PGlite instance */
  }

  async #checkout(): Promise<PgliteClient> {
    while (this.#checkedOut) {
      await new Promise<void>((resolve) => this.#waiting.push(resolve));
    }
    this.#checkedOut = true;
    return new PgliteClient(this.db, () => {
      this.#checkedOut = false;
      this.#waiting.shift()?.();
    });
  }
}

/** Wrap `db` as the `pg.Pool` `extract()` takes. The cast is the point: this is
 *  a structural stand-in, not a node-pg pool. */
export function pglitePool(db: PGlite): Pool {
  return new PglitePool(db) as unknown as Pool;
}
