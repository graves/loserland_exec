# loserland_exec

## Load a DLL from memory

A neat example of translating unsafe C code to Rust.

To quote [fancycode](https://github.com/fancycode):

```c
The default windows API functions to load external libraries into a program
(LoadLibrary, LoadLibraryEx) only work with files on the filesystem. 
```

This makes it difficult to execute code given a stream of bytes who don't
reside on the Windows Filesystem.

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

## Status

Pre-alpha? Honestly looking for help documenting this.

## Contributing

Please feel free to [open an
issue](https://github.com/graves/loserland_exec/issues), send me an email:
b@o0.si, or reach out on [twitter](https://twitter.com/dqt)

Questions, comments, concerns, and contributions will be met with compassion.
None of us speak the same language. 


### References

* https://github.com/fancycode/MemoryModule
* https://github.com/deptofdefense/SalSA/wiki/PE-File-Format
