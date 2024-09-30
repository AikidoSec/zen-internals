# Zen Internals library.
Zen Internals is a library that can be used via FFI in different languages. Contains algorithms to detect:
- Shell Injections (WIP)
- SQL Injections

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
$ npm install @aikidosec/zen-internals
```

```bash
$ yarn add @aikidosec/zen-internals
```

### API 

#### SQL injection detection

```js
const { wasm_detect_sql_injection } = require("@aikidosec/zen-internals");

const detected = wasm_detect_sql_injection(
    `SELECT * FROM users WHERE id = '' OR 1=1 -- '`, // query
    `' OR 1=1 -- `, // user input
    9 // MySQL dialect
);

console.log(detected); // true
```

See [list of dialects](https://github.com/AikidoSec/zen-internals/blob/main/src/sql_injection/helpers/select_dialect_based_on_enum.rs#L18)
