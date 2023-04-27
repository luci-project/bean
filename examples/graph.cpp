// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>
#include <dlh/math.hpp>

#include <bean/file.hpp>

struct normalize {
	const char * s;
	explicit normalize(const char * s) : s(s) {}
};

static inline BufferStream& operator<<(BufferStream& bs, const normalize& norm) {
	bool r = false;
	for (const char * c = norm.s; c != nullptr && *c != '\0'; c++)
		if ((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9')) {
			bs << *c;
			r = false;
		} else if (!r) {
			bs << '_';
			r = true;
		}
	return bs;
}


int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Call/Dependency Graph of ELF binary (for Graphviz Dot)" << endl << endl
		     << "   Usage: " << argv[0] << " [-c] [-e] [-E] [-f FONT] [-r] [-s] [-k] [-b FOLDER] [-v[v[v]]] ELF-FILE[S]"<< endl << endl
		     << "Parameters:" << endl
		     << "  -c    concentrate edges in dot output" << endl
		     << "  -e    show external visible symbols" << endl
		     << "  -E    highlight entry point" << endl
		     << "  -f    font to use in dot output" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -R    reconstruct relocations" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -k    keep unused symbols" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "  -v    cluster sections" << endl
		     << "  -vv   ... and show offsets" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		if (Bean::diet())
			cerr << "[Diet build]" << endl;
		return EXIT_FAILURE;
	}

	Bean::Verbosity verbose = Bean::NONE;
	uint32_t flags = Bean::FLAG_NONE;
	bool entry = false;
	bool dbgsym = false;
	bool external = false;
	bool concentrate = false;
	const char * base = nullptr;
	const char * font = "Fira Mono";

	for (int i = 1; i < argc; i++) {
		if (String::compare(argv[i], "-e") == 0) {
			external = true;
		} else if (String::compare(argv[i], "-E") == 0) {
			entry = true;
		} else if (String::compare(argv[i], "-f") == 0) {
			font = argv[++i];
		} else if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-k") == 0) {
			flags |= Bean::FLAG_KEEP_UNUSED_SYMBOLS;
		} else if (String::compare(argv[i], "-r") == 0) {
			flags |= Bean::FLAG_RESOLVE_INTERNAL_RELOCATIONS;
		} else if (String::compare(argv[i], "-R") == 0) {
			flags |= Bean::FLAG_RECONSTRUCT_RELOCATIONS;
		} else if (String::compare(argv[i], "-b") == 0) {
			base = argv[++i];
		} else if (String::compare(argv[i], "-c") == 0) {
			concentrate = true;
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
			BeanFile file(argv[i], dbgsym, flags, base);

			cout << "digraph " << normalize(argv[i]) << " {" << endl
			     << "\tnode [shape=rectangle fontname=\"" << font << "\"]" << endl
			     << "\tbeautify=true" << endl
			     << "\trankdir=LR" << endl;
			if (concentrate)
				cout << "\tconcentrate=true;" << endl;
			const char * section = nullptr;
			for (const auto & sym : file.bean.symbols) {
				if (verbose > Bean::NONE) {
				 	if (section == nullptr || String::compare(section, sym.section.name) != 0) {
						if (section != nullptr)
							cout << "\t}" << endl;
						section = sym.section.name;
						unsigned fgcolor = 0x666666;
						unsigned bgcolor = 0xeeeeee;
						if (sym.section.executable) {
							fgcolor |= 0x990000;
							bgcolor |= 0xff0000;
						}
						if (sym.section.writeable) {
							fgcolor |= 0x99 << ((sym.section.flags & Bean::Symbol::Section::SECTION_RELRO) != 0 ? 8 : 0);
							bgcolor |= 0xff << ((sym.section.flags & Bean::Symbol::Section::SECTION_RELRO) != 0 ? 8 : 0);
						}
						cout << "\tsubgraph cluster_" << normalize(section) << '{' << endl
						     << "\t\tstyle=\"filled,rounded\"" << endl
						     << "\t\tfillcolor=\"#" << setw(6) << hex << bgcolor << '"' << endl
						     << "\t\tfontcolor=\"#" << setw(6) << hex << fgcolor << '"' << endl
						     << "\t\tpencolor=\"#" << setw(6) << hex << fgcolor << '"' << endl
						     << reset
						     << "\t\tlabel=<<I>" << section << "</I>>" << endl;
					}
					cout << '\t';
				}
				cout << "\tm" << hex << sym.address << "[label=<";
				if (String::len(sym.name) > 0)
					cout << "<B>" << sym.name << "</B><BR/>";
				cout << setfill('0') << hex << setw(16) << sym.id.internal
				     << "<BR/><FONT COLOR=\"#aaaaaa\">" << setfill('0') << hex << setw(16) << sym.id.external
				     << "</FONT><BR/><FONT POINT-SIZE=\"8\">";
			 	switch (sym.bind) {
			 		case Bean::Symbol::BIND_WEAK:   cout << "weak ";    break;
			 		case Bean::Symbol::BIND_LOCAL:  cout << "local ";   break;
			 		case Bean::Symbol::BIND_GLOBAL: cout << "global ";  break;
			 	}
				switch (sym.type) {
					case Bean::Symbol::TYPE_NONE:           cout << "notype, ";    break;
					case Bean::Symbol::TYPE_OBJECT:         cout << "object, ";    break;
					case Bean::Symbol::TYPE_FUNC:           cout << "function, ";  break;
					case Bean::Symbol::TYPE_SECTION:        cout << "section, ";   break;
					case Bean::Symbol::TYPE_FILE:           cout << "filename, ";  break;
					case Bean::Symbol::TYPE_COMMON:         cout << "common, ";    break;
					case Bean::Symbol::TYPE_TLS:            cout << "TLS, ";       break;
					case Bean::Symbol::TYPE_INDIRECT_FUNC:  cout << "indirect function, ";  break;
				}
				cout << dec << sym.size << "B @ 0x" << hex << sym.address << reset << "</FONT>>]" << endl;
			}
			if (section != nullptr)
				cout << "\t}" << endl;
			if (external)
				cout << "\textern [style=\"filled\" color=\"#0000ff\" fontcolor=\"#ffffff\" label=<<B>EXTERN</B>>]" << endl;
			if (entry && file.bean.symbols.find(file.binary.content.header.entry()))
				cout << "\tentry [shape=\"oval\" style=\"filled\" color=\"#ff0000\" fontcolor=\"#ffffff\" label=<<B>ENTRY</B>>] " << endl
				     << "\tentry -> m" << hex << file.binary.content.header.entry() << " [arrowhead=\"open\" color=\"#ff0000\" penwidth=\"2\"]" << endl;
			for (const auto & sym : file.bean.symbols) {
				if (external && sym.bind == Bean::Symbol::BIND_GLOBAL)
					cout << "\textern -> m" << hex << sym.address << " [arrowhead=\"dot\" color=\"#0000ff\" penwidth=\"2\"]" << endl;
				for (const auto & ref : sym.refs) {
					auto ref_sym = file.bean.symbols.floor(ref);
					if (ref_sym && Bean::TLS::is_tls(ref_sym->address) == Bean::TLS::is_tls(ref)) {
						cout << "\tm" << hex << sym.address << " -> m" << ref_sym->address;
						if (verbose >= Bean::DEBUG && ref_sym->address != ref)
							cout << " [label=<<FONT FACE=\"" << font << "\" POINT-SIZE=\"8\">+" << dec << (ref - ref_sym->address) << "</FONT>>]";
						cout << endl;
					}
				}
			}
			cout << '}' << endl;
		}
	}

	return EXIT_SUCCESS;
}
