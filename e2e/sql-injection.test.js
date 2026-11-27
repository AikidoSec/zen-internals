const { after, before, describe, test } = require("node:test");
const assert = require("node:assert/strict");
const { wasm_detect_sql_injection } = require("../pkg/zen_internals");
const cases = require("./cases");
const databases = require("./databases");

const VERDICTS = {
  0: "safe",
  1: "injection",
  2: "internal error",
  3: "failed to tokenize",
};

// e.g. injection: "' OR 1=1 -- " in `SELECT * FROM users WHERE name = '${input}'`
function testName({ sql, input, expect }) {
  const handler = sql.toString().replace(/^.*?=>\s*/s, "");
  return `${expect}: ${JSON.stringify(input)} in ${handler}`;
}

for (const database of databases) {
  describe(database.name, () => {
    let db;

    before(async () => {
      db = await database.connect();
    });

    after(() => db?.close());

    for (const testCase of cases) {
      const { databases, sql, input, expect } = testCase;
      if (!databases.includes(database.family)) {
        continue;
      }

      test(testName(testCase), { timeout: 10_000 }, async () => {
        for (const statement of database.schema) {
          await db.query(statement);
        }

        const query = sql(input, db);

        try {
          await db.query(query);
        } catch (error) {
          assert.fail(
            `${database.name} rejected the query, so this case isn't real\nquery: ${query}\nerror: ${error.message}`
          );
        }

        const verdict = VERDICTS[wasm_detect_sql_injection(query, input, database.dialect)];
        assert.equal(verdict, expect, `query: ${query}\ninput: ${input}`);
      });
    }
  });
}
