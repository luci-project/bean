// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Hash ELF binary" << endl << endl
		     << "   Usage: " << argv[0] << " [-r] [-R] [-s] [-k] [-b FOLDER] [-v[v[v]]] ELF-FILE[S]"<< endl << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -R    reconstruct relocations" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -k    keep unused symbols" << endl
		     << "  -a    use all symbol attributes for internal ID hash" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "  -v    list address and names" << endl
		     << "  -vv   ... and dissassemble code" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		if (Bean::diet())
			cerr << "[Diet build with limited functionality]" << endl;
		return EXIT_FAILURE;
	}

	Bean::Verbosity verbose = Bean::NONE;
	uint32_t flags = Bean::FLAG_NONE;
	bool reloc = false;
	bool dbgsym = false;
	const char * base = nullptr;

	for (int i = 1; i < argc; i++) {
		if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-k") == 0) {
			flags |= Bean::FLAG_KEEP_UNUSED_SYMBOLS;
		} else if (String::compare(argv[i], "-r") == 0) {
			flags |= Bean::FLAG_RESOLVE_INTERNAL_RELOCATIONS;
		} else if (String::compare(argv[i], "-R") == 0) {
			flags |= Bean::FLAG_RECONSTRUCT_RELOCATIONS;
		} else if (String::compare(argv[i], "-a") == 0) {
			flags |= Bean::FLAG_HASH_ATTRIBUTES_FOR_ID;
		} else if (String::compare(argv[i], "-b") == 0) {
			base = argv[++i];
		} else if (String::compare(argv[i], "-v", 2) == 0) {
			for (size_t j = 1; argv[i][j] != '\0'; j++) {
				if (argv[i][j] == 'v') {
					verbose = static_cast<Bean::Verbosity>(1 + static_cast<uint8_t>(verbose));
				} else {
					cerr << "Unsupported parameter '" << argv[i] << endl;
					return EXIT_FAILURE;
				}
			}
		} else if (argv[i][0] == '-') {
			cerr << "Unsupported parameter '" << argv[i] << endl;
			return EXIT_FAILURE;
		} else {
			if (verbose >= Bean::DEBUG)
				flags |= Bean::FLAG_DEBUG;

			BeanFile file(argv[i], dbgsym, flags, base);
			cout << "# " << file.binary.path << " (" << file.binary.size << " bytes):" << endl;
			file.bean.dump(cout, verbose);
			cout << endl;
		}
	}

	return EXIT_SUCCESS;
}
