# Zen Internals library.

Zen Internals is a library that can be used via FFI in different languages. Contains algorithms to detect:

-   Shell Injections (WIP)
-   SQL Injections
- JS Code Injections
## Python FFI Example code :

```py
import ctypes
zen_internals = ctypes.CDLL("target/release/libzen_internals.so")

if __name__ == "__main__":
    command = "whoami | shell".encode("utf-8")
    userinput = "whoami".encode("utf-8")
    result = zen_internals.detect_shell_injection(command, userinput)
    print("Result", bool(result))
```

## Node.js bindings

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
    9 // MySQL dialect
);

console.log(detected); // 1
```

See [list of dialects](https://github.com/AikidoSec/zen-internals/blob/main/src/sql_injection/helpers/select_dialect_based_on_enum.rs#L18)

### JS injection detection

```js
const { wasm_detect_js_injection } = require("./some-directory/zen_internals");

const detected = wasm_detect_js_injection(
    `const x = 1; console.log(x); // ;`, // code
    `1; console.log(x); // ` // user input
);

console.log(detected); // 1
```

By default, the function expects the input to be JavaScript code (CJS or ESM). TypeScript is also supported—specify the appropriate type by passing the corresponding [source type number](https://github.com/AikidoSec/zen-internals/blob/main/src/js_injection/helpers/select_sourcetype_based_on_enum.rs) as the third argument.
