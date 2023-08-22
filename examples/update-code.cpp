// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <dlh/parser/string.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>
#include <dlh/is_in.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	Bean::Verbosity verbose = Bean::NONE;
	Bean::ComparisonMode comparison_mode = Bean::COMPARE_EXTENDED;
	uint32_t flags = Bean::FLAG_NONE;
	bool dbgsym = false;
	bool only_branch = false;
	bool only_executable = false;
	bool use_symbol_names = false;
	const char * old_base = nullptr;
	const char * new_base = nullptr;
	const char * old_path = nullptr;
	const char * new_path = nullptr;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;

	for (int i = 1; i < argc; i++) {
		 if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-n") == 0) {
			use_symbol_names = false;
		} else if (String::compare(argv[i], "-B") == 0) {
			only_branch = true;
		} else if (String::compare(argv[i], "-X") == 0) {
			only_executable = true;
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
		     << "   Usage: " << argv[0] << " [-r] [-R] [-n] [-s] [-k] [-m[THRESHOLD]] [-b [OLD]BASE [-b NEWBASE]] [-v[v[v]]] OLD NEW" << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -R    reconstruct relocations" << endl
		     << "  -B    consider only relocations on branching instructions" << endl
		     << "  -X    consider only relocations to executable section" << endl
		     << "  -n    ignore symbol names" << endl
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

	BeanFile old_file(old_path, dbgsym, flags, old_base);
	BeanFile new_file(new_path == nullptr ? old_path : new_path, dbgsym, flags, new_base == nullptr ? old_base : new_base);

	const auto & map = old_file.bean.map(new_file.bean, use_symbol_names);

	for (const auto & sym : old_file.bean.symbols) {
		if (sym.rels.empty())
			continue;
		sym.dump(cout, verbose, &old_file.bean.symbols);
		bool is_func = sym.section.executable && is(sym.type).in(Bean::Symbol::TYPE_UNKNOWN, Bean::Symbol::TYPE_FUNC, Bean::Symbol::TYPE_INDIRECT_FUNC);

		// Full redirect
		if (is_func) {
			if (const auto & new_target_sym = new_file.bean.symbols.floor(sym.address)) {
				auto address = sym.address;
				// endbr instruction is 4 bytes
				if ((sym.flags & Bean::Symbol::SYMBOL_USING_CET) != 0)
					address += 4;
				cout << "\e[32m - redirecting " << hex << old_path << ':' << address << " to " << new_path << ':' << new_target_sym->address << "\e[0m" << endl;
			}
		}
		// Check all relocations
		for (const auto rel : sym.rels) {
			// for each relocation target check if there is a new one
			if (const auto new_target = map.find(rel.target)) {
				// The symbol to which the target maps
				const auto & new_target_sym = new_file.bean.symbols.floor(new_target->value);
				assert(new_target_sym);
				if (only_executable && !new_target_sym->section.executable)
					continue;

				// check relocation information
				bool is_branch = (rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_BRANCH) != 0;
				if (only_branch && !is_branch)
					continue;
				bool is_local = (rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_LOCAL) != 0;

				if (is_func && is_branch && is_local) {
					// If the target offset id is identical, the control flow can be redirected
					const auto old_target_offset_id = sym.offset_ids.find(rel.target - sym.address);
					const auto new_target_offset_id = new_target_sym->offset_ids.find(new_target->value - new_target_sym->address);
					if (old_target_offset_id && new_target_offset_id && old_target_offset_id->value == new_target_offset_id->value)
						cout << "\e[32m - redirecting " << hex << old_path << ':' << (rel.offset - rel.instruction_offset) << " to " << new_path << ':' << new_target->value << "\e[0m" << endl;
					else
						cout << "\e[31m - skipping " << hex << old_path << ':' << (rel.offset - rel.instruction_offset) << " - different offset ID between " << rel.target << " and " << new_target->value << "\e[0m" << endl;
				} else {
					cout << "\e[32m - relocating " << hex << old_path << ':' << rel.offset << " to " << new_path << ':' << new_target->value << "\e[0m" << endl;
				}
			} else {
				cout << "\e[31m - skipping " << hex << old_path << ':' << rel.offset << " - no target found\e[0m" << endl;
			}
		}
		cout << "\e[0m" << endl;
	}
}
