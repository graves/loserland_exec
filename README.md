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

```rust
extern crate loserland_exec;

use std::fs::File;

// helloworld.dll exports a function named callme
let mut dll_file = File::open("helloworld.dll").unwrap();
let mut dll_data = Vec::new();

// Read the dll file into a vector of bytes so we can pretend we got them from anywhere
dll_file.read_to_end(&mut dll_data).unwrap();

// Find the function exported by our dll in memory
let callme = loserland_exec::get_proc("callme", &dll_data) as *const ();

// Execute the code
(callme)(); // Hello from plugin!
```

## Status

Looking for help writing up in-depth documentation showing how the memory is laid out and code is executed. Would also like to add linux and darwin compatability.

## Contributing

Please feel free to [open an
issue](https://github.com/graves/loserland_exec/issues) or reach out on [twitter](https://twitter.com/dqt)

Questions, comments, concerns, and contributions will be met with compassion.

### References

* https://github.com/fancycode/MemoryModule
* https://github.com/deptofdefense/SalSA/wiki/PE-File-Format
