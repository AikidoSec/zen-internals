// `sql` is the route handler: it puts the input in the query, or escapes it with `db.escape`.
// The query runs on a fresh `users` table (id, name, email) and must succeed on every listed database.

const ALL = ["postgres", "mysql", "mariadb", "sqlite", "clickhouse"];
const MYSQL = ["mysql", "mariadb"];

module.exports = [
  {
    databases: ALL,
    sql: (input) => `SELECT * FROM users WHERE name = '${input}'`,
    input: "' OR 1=1 -- ",
    expect: "injection",
  },
  {
    databases: ALL,
    sql: (input, db) => `SELECT * FROM users WHERE name = ${db.escape(input)}`,
    input: "' OR 1=1 -- ",
    expect: "safe",
  },
  {
    // ClickHouse rejects UNION without ALL or DISTINCT
    databases: ALL,
    sql: (input) => `SELECT id, name FROM users WHERE name = '${input}'`,
    input: "' UNION ALL SELECT id, email FROM users -- ",
    expect: "injection",
  },
  {
    // ClickHouse rejects multiple statements
    databases: ["postgres", "mysql", "mariadb", "sqlite"],
    sql: (input) => `SELECT * FROM users WHERE name = '${input}'`,
    input: "'; DROP TABLE users; -- ",
    expect: "injection",
  },
  {
    databases: ALL,
    sql: (input) => `SELECT * FROM users WHERE id = ${input}`,
    input: "1 OR 1=1",
    expect: "injection",
  },
  {
    databases: ALL,
    sql: (input) => `SELECT * FROM users WHERE id = ${input}`,
    input: "-1",
    expect: "safe",
  },
  {
    databases: ALL,
    sql: (input) => `SELECT * FROM users WHERE id IN (${input})`,
    input: "1,2",
    expect: "safe",
  },
  {
    databases: ALL,
    sql: (input) => `SELECT * FROM users ORDER BY ${input}`,
    input: "name DESC",
    expect: "safe",
  },
  {
    databases: MYSQL,
    sql: (input) => `SELECT * FROM users WHERE name = '${input}'`,
    input: "' OR 1=1 # ",
    expect: "injection",
  },
  {
    // https://github.com/AikidoSec/zen-internals/pull/205
    databases: MYSQL,
    sql: (input, db) => `SELECT * FROM users WHERE name = ${db.escape(input)}`,
    input: "hello\\",
    expect: "safe",
  },
  {
    databases: ["sqlite"],
    sql: (input) => `SELECT * FROM users WHERE id = '${input}'`,
    input: "1' OR $$ IS NULL -- ",
    expect: "injection",
  },
];
