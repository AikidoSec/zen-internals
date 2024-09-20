# Zen Rust library
Zen Rust library is a library that can be used via FFI in different languages. Contains vulnerability code, like : 
- shell_injection

## Python FFI Example code : 
```py
import ctypes
zen_rustlib = ctypes.CDLL("target/release/libzen_rustlib.so")

if __name__ == "__main__":
    command = "whoami | shell".encode("utf-8")
    userinput = "whoami".encode("utf-8")
    result = zen_rustlib.detect_shell_injection(command, userinput)
    print("Result", bool(result))
```
For build_route_from_url : 
```py
import ctypes
zen_rustlib = ctypes.CDLL("target/release/libzen_rustlib.so")
zen_rustlib.build_route_from_url.restype = ctypes.c_char_p

if __name__ == "__main__":
    url = "https://aikido.dev/1234/".encode("utf-8")
    result = zen_rustlib.build_route_from_url(url)
    print("Result", result.decode("utf-8"))
```
