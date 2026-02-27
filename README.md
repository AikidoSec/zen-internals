# Zen Internals library

[![Codecov](https://img.shields.io/codecov/c/github/AikidoSec/zen-internals?style=flat-square)](https://app.codecov.io/gh/aikidosec/zen-internals)

Zen Internals is a library that can be used via FFI in different languages. Contains algorithms to detect:

- SQL Injections
- JS Code Injections

## Return codes

| Return Code | Description                       |
| ----------- | --------------------------------- |
| `0`         | Successful, no injection detected |
| `1`         | Successful, injection detected    |
| `2`         | Error occurred                    |
| `3`         | Failed to tokenize SQL            |

## Python FFI Example code

```py
import ctypes

zen_internals = ctypes.CDLL("target/release/libzen_internals.so")

if __name__ == "__main__":
    query = "SELECT * FROM users WHERE id = '' OR 1=1 -- '".encode("utf-8")
    userinput = "' OR 1=1 -- ".encode("utf-8")
    dialect = 9  # MySQL dialect

    result = zen_internals.detect_sql_injection(
        query, len(query), userinput, len(userinput), dialect
    )
    print("Result", result)
```

See [list of dialects](https://github.com/AikidoSec/zen-internals/blob/main/src/sql_injection/helpers/select_dialect_based_on_enum.rs#L18)

## Node.js bindings (using WASM)

### Install

```bash
curl -L https://github.com/AikidoSec/zen-internals/releases/download/$VERSION/zen_internals.tgz -o zen_internals.tgz
curl -L https://github.com/AikidoSec/zen-internals/releases/download/$VERSION/zen_internals.tgz.sha256sum -o zen_internals.tgz.sha256sum
sha256sum -c zen_internals.tgz.sha256sum
tar -xzf zen_internals.tgz some-directory
```

### API

#### SQL injection detection

```js
const { wasm_detect_sql_injection } = require("./some-directory/zen_internals");

const detected = wasm_detect_sql_injection(
    `SELECT * FROM users WHERE id = '' OR 1=1 -- '`, // query
    `' OR 1=1 -- `, // user input
    9, // MySQL dialect
);

console.log(detected); // 1
```

See [list of dialects](https://github.com/AikidoSec/zen-internals/blob/main/src/sql_injection/helpers/select_dialect_based_on_enum.rs#L18)

#### JS injection detection

```js
const { wasm_detect_js_injection } = require("./some-directory/zen_internals");

const detected = wasm_detect_js_injection(
    `const x = 1; console.log(x); // ;`, // code
    `1; console.log(x); // `, // user input
);

console.log(detected); // 1
```

By default, the function expects the input to be JavaScript code (CJS or ESM). TypeScript is also supported by specifying the appropriate type as the third argument with corresponding [source type number](https://github.com/AikidoSec/zen-internals/blob/main/src/js_injection/helpers/select_sourcetype_based_on_enum.rs).

#### IDOR SQL analysis

Analyzes SQL queries to extract tables and filters for IDOR (Insecure Direct Object Reference) protection.

```js
const { wasm_idor_analyze_sql } = require("./some-directory/zen_internals");

const result = wasm_idor_analyze_sql(
    `SELECT * FROM users u WHERE u.tenant_id = $1`, // query
    9, // PostgreSQL dialect
);

console.log(JSON.parse(result));
// [
//   {
//     kind: "select",
//     tables: [{ name: "users", alias: "u" }],
//     filters: [{ table: "u", column: "tenant_id", value: "$1" }]
//   }
// ]

const insertResult = wasm_idor_analyze_sql(
    `INSERT INTO users (name, tenant_id) VALUES ('John', $1)`,
    9,
);

console.log(JSON.parse(insertResult));
// [
//   {
//     kind: "insert",
//     tables: [{ name: "users" }],
//     filters: [],
//     insert_columns: [[{ column: "name", value: "John" }, { column: "tenant_id", value: "$1" }]]
//   }
// ]

// Column-to-column equality in JOIN ON / WHERE conditions is resolved transitively.
// If one side has a known value, the other inherits it as an additional filter.
const joinResult = wasm_idor_analyze_sql(
    `SELECT r.* FROM requests r JOIN tenants t ON r.sys_group_id = t.sys_group_id WHERE t.sys_group_id = $1`,
    9,
);

console.log(JSON.parse(joinResult));
// [
//   {
//     kind: "select",
//     tables: [{ name: "requests", alias: "r" }, { name: "tenants", alias: "t" }],
//     filters: [
//       { table: "t", column: "sys_group_id", value: "$1", "is_placeholder": true },
//       { table: "r", column: "sys_group_id", value: "$1", "is_placeholder": true }
//     ]
//   }
// ]
```

## FFI IDOR SQL analysis

```py
import ctypes
import json

zen_internals = ctypes.CDLL("target/release/libzen_internals.so")
zen_internals.idor_analyze_sql_ffi.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_int,
]
zen_internals.idor_analyze_sql_ffi.restype = ctypes.c_char_p
zen_internals.free_string.argtypes = [ctypes.c_char_p]

def analyze_sql(query_str, dialect):
    query = query_str.encode("utf-8")
    query_buffer = (ctypes.c_uint8 * len(query)).from_buffer_copy(query)
    result_ptr = zen_internals.idor_analyze_sql_ffi(query_buffer, len(query), dialect)
    result = json.loads(result_ptr.decode("utf-8"))
    zen_internals.free_string(result_ptr)
    return result

print(analyze_sql("SELECT * FROM users u WHERE u.tenant_id = $1", 9))
# [
#   {
#     "kind": "select",
#     "tables": [{ "name": "users", "alias": "u" }],
#     "filters": [{ "table": "u", "column": "tenant_id", "value": "$1" }]
#   }
# ]

print(analyze_sql("INSERT INTO users (name, tenant_id) VALUES ('John', $1)", 9))
# [
#   {
#     "kind": "insert",
#     "tables": [{ "name": "users" }],
#     "filters": [],
#     "insert_columns": [[{ "column": "name", "value": "John" }, { "column": "tenant_id", "value": "$1" }]]
#   }
# ]
```
