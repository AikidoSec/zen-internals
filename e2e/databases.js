const { DatabaseSync } = require("node:sqlite");
const mysql = require("mysql2/promise");
const pg = require("pg");

// Hosts and password must match compose.yml
const PASSWORD = "zen";

// e.g. mysql 8.0 runs in service mysql-8-0
const host = (family, version) => `${family}-${version.replaceAll(".", "-")}`;

const INSERT_USERS =
  "INSERT INTO users VALUES (1, 'Alice', 'alice@example.com'), (2, 'Bob', 'bob@example.com')";

const SCHEMA = [
  "DROP TABLE IF EXISTS users",
  "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255))",
  INSERT_USERS,
];

function postgres(version) {
  return {
    name: `postgres ${version}`,
    family: "postgres",
    dialect: 9,
    schema: SCHEMA,
    async connect() {
      const client = new pg.Client({
        host: host("postgres", version),
        user: "postgres",
        password: PASSWORD,
      });
      await client.connect();

      return {
        // Without parameters, pg uses the simple query protocol (allows stacked queries)
        query: (sql) => client.query(sql),
        escape: (value) => client.escapeLiteral(value),
        close: () => client.end(),
      };
    },
  };
}

function mysqlLike(family, version) {
  return {
    name: `${family} ${version}`,
    family,
    dialect: 8,
    schema: SCHEMA,
    async connect() {
      const connection = await mysql.createConnection({
        host: host(family, version),
        user: "root",
        password: PASSWORD,
        database: "zen",
        multipleStatements: true,
      });

      return {
        query: (sql) => connection.query(sql),
        escape: (value) => connection.escape(value),
        close: () => connection.end(),
      };
    },
  };
}

function clickhouse(version) {
  return {
    name: `clickhouse ${version}`,
    family: "clickhouse",
    dialect: 3,
    schema: [
      "DROP TABLE IF EXISTS users",
      "CREATE TABLE users (id UInt32, name String, email String) ENGINE = Memory",
      INSERT_USERS,
    ],
    connect() {
      const query = async (sql) => {
        const response = await fetch(
          `http://${host("clickhouse", version)}:8123/?wait_end_of_query=1`,
          {
            method: "POST",
            headers: {
              "X-ClickHouse-User": "default",
              "X-ClickHouse-Key": PASSWORD,
            },
            body: sql,
          }
        );
        const body = await response.text();
        if (!response.ok) {
          throw new Error(body);
        }
        return body;
      };

      return {
        query,
        escape: (value) =>
          `'${value.replaceAll("\\", "\\\\").replaceAll("'", "\\'")}'`,
        close: () => {},
      };
    },
  };
}

function sqlite() {
  return {
    name: `sqlite ${process.versions.sqlite}`,
    family: "sqlite",
    dialect: 12,
    schema: SCHEMA,
    connect() {
      const db = new DatabaseSync(":memory:");

      return {
        query: (sql) => db.exec(sql),
        // node:sqlite has no escape function
        escape: (value) => `'${value.replaceAll("'", "''")}'`,
        close: () => db.close(),
      };
    },
  };
}

module.exports = [
  postgres("14"),
  postgres("18"),
  mysqlLike("mysql", "8.0"),
  mysqlLike("mysql", "9.7"),
  mysqlLike("mariadb", "10.6"),
  mysqlLike("mariadb", "11.8"),
  clickhouse("24.8"),
  clickhouse("25.8"),
  sqlite(),
];
