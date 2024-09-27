# Zen Internals library.
Zen Internals is a library that can be used via FFI in different languages. Contains vulnerability code, like : 
- Shell Injection (WIP)
- SQL Injection

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