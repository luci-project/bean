// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <dlh/parser/string.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>
#include <dlh/is_in.hpp>

#include <bean/file.hpp>
#include <bean/update.hpp>

Bean::Verbosity verbose = Bean::NONE;

struct Data {
	BeanFile file;
	const char * path;

	void dump(uintptr_t address) {
		cout << path << ":0x" << hex << address;
		if (const auto & sym = file.bean.symbols.floor(address)) {
			cout << " (";
			if (String::len(sym->name) > 0)
				cout << sym->name;
			else
				sym->id.dump(cout);
			cout << " + " << dec << address - sym->address << ')';
		}
	}

	void header(uintptr_t address) {
		static uintptr_t prev = -1;
		if (const auto & sym = file.bean.symbols.floor(address))
			if (sym->address != prev) {
				sym->dump(cout << endl, verbose, &file.bean.symbols);
				prev = sym->address;
			}
	}
};

static bool redirect(uintptr_t from, uintptr_t to, size_t size, Data * custom) {
	custom[0].header(from);
	cout << "\e[33m - redirecting ";
	custom[0].dump(from);
	if (size > 0)
		cout << " [" << size << " bytes]";
	cout << " to ";
	custom[1].dump(to);
	cout << "\e[0m" << endl;
	return true;
}

static bool relocate(const Bean::SymbolRelocation & rel, uintptr_t to, const Bean::Symbol & target, Data * custom) {
	custom[0].header(rel.offset);
	(void)target;
	cout << "\e[32m - relocating ";
	custom[0].dump(rel.offset);
	cout << " to ";
	custom[1].dump(to);
	cout << "\e[0m" << endl;
	return true;
}

static void skipmsg(uintptr_t from, uintptr_t to, const char * reason, Data * custom) {
	custom[0].header(from);
	cout << "\e[31m - skipping ";
	custom[0].dump(from);
	if (to != 0) {
		cout << " to ";
		custom[1].dump(to);
	}
	if (reason != nullptr)
		cout << " - " << reason;
	cout << "\e[0m" << endl;
}

int main(int argc, const char *argv[]) {
	Bean::ComparisonMode comparison_mode = Bean::COMPARE_EXTENDED;
	uint32_t flags = Bean::FLAG_NONE;
	bool dbgsym = false;
	uint32_t update_flags = BeanUpdate::FLAG_NONE;
	const char * old_base = nullptr;
	const char * new_base = nullptr;
	const char * old_path = nullptr;
	const char * new_path = nullptr;

	for (int i = 1; i < argc; i++) {
		 if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-n") == 0) {
			update_flags |= BeanUpdate::FLAG_USE_SYMBOL_NAMES;
		} else if (String::compare(argv[i], "-t") == 0) {
			update_flags |= BeanUpdate::FLAG_INCLUDE_TRAMPOLINES;
		} else if (String::compare(argv[i], "-B") == 0) {
			update_flags |= BeanUpdate::FLAG_ONLY_BRANCH_RELS;
		} else if (String::compare(argv[i], "-X") == 0) {
			update_flags |= BeanUpdate::FLAG_ONLY_EXECUTABLE;
		} else if (String::compare(argv[i], "-k") == 0) {
			flags |= Bean::FLAG_KEEP_UNUSED_SYMBOLS;
		} else if (String::compare(argv[i], "-r") == 0) {
			flags |= Bean::FLAG_RESOLVE_INTERNAL_RELOCATIONS;
		} else if (String::compare(argv[i], "-R") == 0) {
			flags |= Bean::FLAG_RECONSTRUCT_RELOCATIONS;
		} else if (String::compare(argv[i], "-a") == 0) {
			flags |= Bean::FLAG_HASH_ATTRIBUTES_FOR_ID;
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
		cerr << "Check how OLD ELF functions would redirect to NEW" << endl << endl
		     << "   Usage: " << argv[0] << " [-r] [-R] [-B] [-X] [-n] [-t] [-s] [-k] [-m[THRESHOLD]] [-b [OLD]BASE [-b NEWBASE]] [-v[v[v]]] OLD NEW" << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -R    reconstruct relocations" << endl
		     << "  -B    consider only relocations on branching instructions" << endl
		     << "  -X    consider only relocations to executable section" << endl
		     << "  -n    ignore symbol names" << endl
			 << "  -t    include trampoline symbols" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -k    keep unused symbols" << endl
		     << "  -a    use all symbol attributes for internal ID hash" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "        (if this is set a second time, it will be used for the second [new] binary)" << endl
		     << "  -i    do not check writeable section with external ID (only internal one) " << endl
		     << "  -ii   do only check executable sections with both IDs, use internal ID for everything else" << endl
		     << "  -iii  rely on internal ID only for comparison (and ignore external one)" << endl
		     << "  -v    list address and names" << endl
		     << "  -vv   ... and dissassemble code" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		if (Bean::diet())
			cerr << "[Diet build with limited functionality]" << endl;
		return EXIT_FAILURE;
	}

	Data data[2] = {
		{ BeanFile{old_path, dbgsym, flags, old_base}, old_path},
		{ BeanFile{new_path == nullptr ? old_path : new_path, dbgsym, flags, new_base == nullptr ? old_base : new_base}, new_path}
	};
	BeanUpdate updater(update_flags);
	updater.process<Data, redirect, relocate, skipmsg>(data[0].file.bean, data[1].file.bean, 0, 0, data);
}
