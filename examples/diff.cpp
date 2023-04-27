// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	Bean::Verbosity verbose = Bean::NONE;
	Bean::ComparisonMode comparison_mode = Bean::COMPARE_EXTENDED;
	uint32_t flags = Bean::FLAG_NONE;
	bool dependencies = false;
	bool dbgsym = false;
	const char * old_base = nullptr;
	const char * new_base = nullptr;
	const char * old_path = nullptr;
	const char * new_path = nullptr;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;

	for (int i = 1; i < argc; i++) {
		if (String::compare(argv[i], "-d") == 0) {
			dependencies = true;
		} else if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-k") == 0) {
			flags |= Bean::FLAG_KEEP_UNUSED_SYMBOLS;
		} else if (String::compare(argv[i], "-r") == 0) {
			flags |= Bean::FLAG_RESOLVE_INTERNAL_RELOCATIONS;
		} else if (String::compare(argv[i], "-R") == 0) {
			flags |= Bean::FLAG_RECONSTRUCT_RELOCATIONS;
		} else if (String::compare(argv[i], "-b") == 0) {
			if (old_base == nullptr) {
				old_base = argv[++i];
			} else if (new_base == nullptr) {
				new_base = argv[++i];
			} else {
				cerr << "Invalid third base parameter " << argv[++i] << endl;
				return EXIT_FAILURE;
			}
		} else if (String::compare(argv[i], "-i", 2) == 0) {
			for (size_t j = 1; argv[i][j] != '\0'; j++) {
				if (argv[i][j] == 'i') {
					comparison_mode = static_cast<Bean::ComparisonMode>(1 + static_cast<uint8_t>(comparison_mode));
				} else {
					cerr << "Unsupported parameter '" << argv[i] << endl;
					return EXIT_FAILURE;
				}
			}
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
		} else if (old_path == nullptr) {
			old_path = argv[i];
		} else if (new_path == nullptr) {
			new_path = argv[i];
		} else {
			cerr << "Ignoring argument " << argv[i] << endl;
		}
	}

	if (verbose >= Bean::DEBUG)
		flags |= Bean::FLAG_DEBUG;

	if (new_path == nullptr && new_base == nullptr) {
		cerr << "Compare ELF binaries A and B" << endl << endl
		     << "   Usage: " << argv[0] << " [-r] [-R] [-d] [-s] [-k] [-b [OLD]BASE [-b NEWBASE]] [-v[v[v]]] OLD NEW" << endl << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -R    reconstruct relocations" << endl
		     << "  -d    include dependencies" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -k    keep unused symbols" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "        (if this is set a second time, it will be used for the second [new] binary)" << endl
		     << "  -i    do not check writeable section with external ID (only internal one) " << endl
		     << "  -ii   do only check executable sections with both IDs, use internal ID for everything else" << endl
		     << "  -iii  rely on internal ID only for comparison (and ignore external one)" << endl
		     << "  -v    list address and names" << endl
		     << "  -vv   ... and dissassemble code" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		if (Bean::diet())
			cerr << "[Diet build]" << endl;
		return EXIT_FAILURE;
	}

	BeanFile old_file(old_path, dbgsym, flags, old_base);
	BeanFile new_file(new_path == nullptr ? old_path : new_path, dbgsym, flags, new_base == nullptr ? old_base : new_base);

	auto diff = new_file.bean.diff(old_file.bean, dependencies, comparison_mode);

	if (verbose == Bean::NONE) {
		Bean::dump(cout, diff);
	} else {
		Bean::Symbol::dump_header(cout << ' ', verbose);
		auto removed = old_file.bean.diff(new_file.bean, dependencies, comparison_mode);
		auto rnext = removed.begin();
		for (const auto & n : new_file.bean) {
			while (rnext != removed.end() && rnext->address <= n.address) {
				rnext->dump(cout, verbose, &old_file.bean.symbols, "\e[0;31m-");
				++rnext;
			}
			bool dbg = false;
			if (diff.contains(n)) {
				n.dump(cout, verbose, &new_file.bean.symbols, "\e[0;32m+");
			} else {
				n.dump(cout, Bean::VERBOSE, &new_file.bean.symbols, "\e[0m ");
			}
		}
		while (rnext != removed.end()) {
			rnext->dump(cout, verbose, &old_file.bean.symbols, "\e[0;31m-");
			++rnext;
		}
		cout << "\e[0m";
	}

	return EXIT_SUCCESS;
}
