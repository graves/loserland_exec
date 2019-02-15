# loserland_exec

## Load a DLL from memory

Don't use this ever.

```
extern crate loserland_exec;

use std::fs::File;

// helloworld.dll exports a function named callme

let mut dll_file = File::open("helloworld.dll").unwrap();
let mut dll_data = Vec::new();
dll_file.read_to_end(&mut dll_data).unwrap();
let proc = loserland_exec::get_proc("callme", &dll_data) as *const ();
let callme: extern "C" fn() = unsafe { std::mem::transmute(proc) };
(callme)(); // Hello from plugin!
```
### References

* https://github.com/fancycode/MemoryModule
* https://github.com/deptofdefense/SalSA/wiki/PE-File-Format
