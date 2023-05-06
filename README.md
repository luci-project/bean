Bean - Binary Explorer & Analyzer
=================================

A library to detect changes of different versions of binaries in the [Executable and Linking Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).


Dependencies
------------

 - [Elfo](https://gitlab.cs.fau.de/luci-project/elfo) is used to access the contents of [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)-Files
 - [Dirty Little Helper](https://gitlab.cs.fau.de/luci-project/dlh) provides the required standard library functions as well as the data structures (tree/hash set/map)
 - [Capstone](http://www.capstone-engine.org/) is used to disassemble the binary sections


Build
-----

After ensuring all submodules are checked out (`git submodule update --init --recursive`),
just run `make`. This will create two static libraries:

 - `libs/libbean.a` contains the binary analyzer
 - `libbean.a` also includes the Bean dependencies (Capstone and DLH)

Examples
--------

The `examples` directory contains a few example programs, which can be built using

    make examples

They are controlled with several similar parameters:

|  Flag  |  Description                                           |
|--------|--------------------------------------------------------|
| `-h`   | print usage information including available parameters |
| `-r`   | resolve (internal) relocations                         |
| `-R`   | try to reconstruct certain relocations                 |
| `-d`   | inherit incompatibility from dependencies              |
| `-s`   | also use (external) debug symbols in analyzer          |
| `-k`   | do not omit unused/empty symbols                       |
| `-b`   | set base directory to search for debug files           |
| `-v`   | verbose output with address and names                  |
| `-vv`  | ... and include dissassembled code                     |
| `-vvv` | ... and show all references and relocations            |

(for a detailed list, use `-h`)


### Hash

Generate the hash values for the symbols in the given ELF files using `bean-hash`:

    ./bean-hash libfoo.so.1.0.0

Use the verbose parameter (`-v`, `-vv`, `-vvv`) for a more detailed overview about the contents used for the hashes.
Disassembled instructions are color-coded to highlight excluded parts for the hashing.
Moreover, all references and relocations are taken into account.


### Diff

Changed symbols of two given ELF files are highlighted in a diff typical manner by `bean-diff`.
Increase the verbosity level for additional information about the changed symbols:

    ./bean-diff -vvv -r -d libfoo.so.1.0.0 libfoo.so.1.0.1


### DiffStat

The util `bean-diffstat` gives a summary of changed symbols between two given ELF files in JSON format:

    ./bean-diffstat -r -d libfoo.so.1.0.0 libfoo.so.1.0.1


### Graph

To visualize the calls and dependencies of an executable, you can use the output of `bean-graph` piped to [Graphviz](https://graphviz.org/) `dot` utility.

    ./bean-graph -e -r -vv libfoo.so.1.0.0 | dot -Tx11

The parameter `-e` highlights external symbols, while `-vv` will cluster the symbols according to their section and show offsets in the call edges.


### Update

Check if an ELF file can be live-updated by another ELF file with `bean-update`

    ./bean-update -r -d -v libfoo.so.1.0.0 libfoo.so.1.0.1

This outputs all symbols with changes and exits with status `0` if updates can be applied.


Tools
-----

the `tools` directory contains several helper scripts written in Bash and Python 3:

 - `dbgsym.py` tries to gather debug binaries for a given binary (according to [GDB](https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html) including the [debuginfod](https://sourceware.org/elfutils/Debuginfod.html) service)
 - `dwarvars.py` extracts variables, datatypes, function declarations etc from debug information, employing `dwarfparse.py` (which itself uses the [pyelftools](https://github.com/eliben/pyelftools) to read the [DWARF](https://dwarfstd.org/) format.
 - `elfvars.py` calculates symbol hashes
 - `elfvarsd.sh` is a wrapper script to run the symbol hashing as a daemon listening on a socket/port
 - `compare.py` gives an overview about changes in multiple different versions of a binary

[pip](https://pypi.org/project/pip/) is used to install the requirements:

    pip install -r requirements.txt

To install the examples and tools (prefixed with `bean-`) in `$HOME/.local/bin` run

    make install

> **Please note:** Partial units, used in compressed DWARF (see Appendix E of the [DWARF4 Standard](https://dwarfstd.org/doc/DWARF4.pdf)), are not supported yet.


Author & License
----------------

*Bean* is part of the *Luci*-project, which is being developed by [Bernhard Heinloth](https://sys.cs.fau.de/person/heinloth) of the [Department of Computer Science 4](https://sys.cs.fau.de/) at [Friedrich-Alexander-Universität Erlangen-Nürnberg](https://www.fau.eu/) and is available under the [GNU Affero General Public License, Version 3 (AGPL v3)](LICENSE.md).
