Bean - Binary Explorer & Analyzer
=================================

A library to detect changes of different versions of binaries in the [Executable and Linking Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).


Dependencies
------------

 - [ELFO](https://gitlab.cs.fau.de/heinloth/elfo) is used to access the contents of [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)-Files
 - [Dirty Little Helper](https://gitlab.cs.fau.de/heinloth/dlh) provides the required standard library functions as well as the data structures (tree/hash set/map)
 - [Capstone](http://www.capstone-engine.org/) is used to disassemble the binary sections


Build
-----

Just run `make`. This will create two static libraries:

 - `libbean.a` contains the binary analyzer
 - `libbean-pack.a` also includes the Bean dependencies (Capstone and DLH)


Examples
--------

The `examples` directory contains a few example programs, which can be built using

    make examples

### Hash

Generate the hash values for the symbols in the given ELF files using `example-hash`
Use the verbose parameter (`-v`, `-vv`, `-vvv`) for additional information about the generation of the hashes:

Disassembled instructions are color-coded to highlight excluded parts for the
hashing. Moreover, all references and relocations are resolved.


### Diff

Changed symbols of two given ELF files are highlighted in a diff typical manner by `example-diff`.
Increase the verbosity level for additional information about the changed
symbols.


### Update

Check if an ELF file can be live-updated by another ELF file with `example-update`


Name
----

Its name origins from the [Disenchantment](https://en.wikipedia.org/wiki/Disenchantment_(TV_series)) [character](https://disenchantment.fandom.com/wiki/Elfo), obviously.
Thanks for all the fun, [Matt](https://en.wikipedia.org/wiki/Matt_Groening)!
