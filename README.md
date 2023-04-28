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

Generate the hash values for the symbols in the given ELF files using `bean-hash`
Use the verbose parameter (`-v`, `-vv`, `-vvv`) for additional information about the generation of the hashes:

Disassembled instructions are color-coded to highlight excluded parts for the
hashing. Moreover, all references and relocations are resolved.


### Diff

Changed symbols of two given ELF files are highlighted in a diff typical manner by `bean-diff`.
Increase the verbosity level for additional information about the changed symbols.


### DiffStat

The util `bean-diffstat` gives a summary of changed symbols between two given ELF files in JSON format.


### Graph

To visualize the calls and dependencies of an executable, you can use the output of `bean-graph` piped to [Graphviz](https://graphviz.org/) `dot` utility.



### Update

Check if an ELF file can be live-updated by another ELF file with `bean-update`


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


Author & License
----------------

*Bean* is part of the *Luci*-project, which is being developed by [Bernhard Heinloth](https://sys.cs.fau.de/person/heinloth) of the [Department of Computer Science 4](https://sys.cs.fau.de/) at [Friedrich-Alexander-Universität Erlangen-Nürnberg](https://www.fau.eu/) and is available under the [GNU Affero General Public License, Version 3 (AGPL v3)](LICENSE.md).


Name
----

Its name origins from the [Disenchantment](https://en.wikipedia.org/wiki/Disenchantment_(TV_series)) [character](https://disenchantment.fandom.com/wiki/Bean), obviously.
Thanks for all the fun, [Matt](https://en.wikipedia.org/wiki/Matt_Groening)!
