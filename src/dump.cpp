#include <bean/bean.hpp>

static void dump_type(BufferStream & bs, Bean::Symbol::Type type) {
	switch (type) {
		case Bean::Symbol::TYPE_NONE:           bs << "none";      break;
		case Bean::Symbol::TYPE_OBJECT:         bs << "object";    break;
		case Bean::Symbol::TYPE_FUNC:           bs << "function";  break;
		case Bean::Symbol::TYPE_SECTION:        bs << "section";   break;
		case Bean::Symbol::TYPE_FILE:           bs << "filename";  break;
		case Bean::Symbol::TYPE_COMMON:         bs << "common";    break;
		case Bean::Symbol::TYPE_TLS:            bs << "TLS";       break;
		case Bean::Symbol::TYPE_INDIRECT_FUNC:  bs << "indirect";  break;
		default:                                bs << "unknown";   break;
	}
}

static void dump_bind(BufferStream & bs, Bean::Symbol::Bind bind) {
	switch (bind) {
		case Bean::Symbol::BIND_WEAK:   bs << "weak";    break;
		case Bean::Symbol::BIND_LOCAL:  bs << "local";   break;
		case Bean::Symbol::BIND_GLOBAL: bs << "global";  break;
		default:                        bs << "unknown"; break;
	}
}

void Bean::Symbol::Identifier::dump(BufferStream& bs) const {
	bs << '{' << setfill('0') << hex << setw(16) << internal
	   << ' ' << setfill('0') << hex << setw(16) << external
	   << '}' << reset;
}

void Bean::Symbol::dump_name(BufferStream& bs) const {
	if (TLS::is_tls(address))
		bs << "TLS:";
	if (name != nullptr && name[0] != '\0')
		bs << "\e[1m" << name << "\e[22m (";
	else
		bs << "unnamed ";

	bs << dec << size << " bytes @ 0x"
	   << hex << address;

	if (bind != Symbol::BIND_LOCAL)
		dump_bind(bs << ", ", bind);

	if (section.name != nullptr)
		bs << ", " << section.name;

	bs << " [r" << (section.writeable ? ((section.flags & Symbol::Section::SECTION_RELRO) != 0 ? '*' : 'w') : '-') << (section.executable ? 'x' : '-') << ']';
	if (name != nullptr && name[0] != '\0')
		bs << ')';
}

Bean::symtree_t::ConstIterator Bean::dump_address(BufferStream & bs, uintptr_t value, const symtree_t & symbols) {
	if (TLS::is_tls(value))
		bs << "TLS:";
	bs << "0x" << hex << TLS::virt_addr(value);
	const auto ref_sym = symbols.floor(value);
	if (ref_sym && Bean::TLS::is_tls(ref_sym->address) == Bean::TLS::is_tls(value)) {
		bs << " <";
		if (ref_sym->name != nullptr)
			bs << ref_sym->name;
		else {
			if (TLS::is_tls(ref_sym->address))
				bs << "TLS:";
			bs << "0x" << hex << TLS::virt_addr(ref_sym->address);
		}

		if (ref_sym->section.name != nullptr)
			bs << '@' << ref_sym->section.name;

		if (ref_sym->address != value)
			bs << " + " << dec << (value - ref_sym->address);
		bs << '>';
	}
	return ref_sym;
}

void Bean::Symbol::dump_header(BufferStream & bs, Verbosity level) {
	if (level <= VERBOSE) {
		bs << "{ID               ID refs         }";
		if (level == VERBOSE)
			bs << " [Ref / Rel / Dep] - Address              Size Type     Bind  Flag Name (Section)";
		bs << endl;
	}
}

void Bean::Symbol::dump(BufferStream & bs, Verbosity level, const symtree_t * symbols, const char * prefix) const {
	bs << prefix;
	if (level <= VERBOSE) {
		id.dump(bs);
		if (level == VERBOSE) {
			bs << " [" << setw(3) << right << refs.size() << " / " << setw(3) << right << rels.size() << " / " << setw(3) << right << deps.size() << "] - "
			   << "0x" << setw(16) << setfill('0') << hex << TLS::virt_addr(address)
			   << dec << setw(7) << setfill(' ') << right << size << ' '
			   << setw(9) << left;
			dump_type(bs, type);
			bs << setw(6) << left;
			dump_bind(bs, bind);
			bs << ' '
			   << (section.writeable ? ((section.flags & Symbol::Section::SECTION_RELRO) != 0 ? 'R' : 'W') : ' ') << (section.executable ? 'X' : ' ') << (TLS::is_tls(address) ? 'T' : ' ');
			if (name != nullptr && name[0] != '\0')
				bs << ' ' << name;
			if (section.name != nullptr)
				bs << " (" << section.name << ')';
		}
		bs << endl;
	} else {
		dump_name(bs);
#ifdef BEAN_VERBOSE
		if (debug != nullptr || refs.size() > 0 || rels.size() > 0 || deps.size() > 0)
			bs << ':';
		bs << endl;

		if (debug != nullptr) {
			size_t i, s = 0;
			do {
				for (i = s; debug[i] != '\0' && debug[i] != '\n'; i++);
				if (i > s) {
					bs << prefix;
					bs.write(debug + s, i - s + 1);
					s = i + 1;
				}
			} while (debug[i] != '\0');
		}
#endif
		if (refs.size() > 0) {
			bs << prefix << "  " << dec << refs.size() << " Reference";
			if (refs.size() != 1)
				bs << 's';
			bs << endl;
			if (level >= TRACE)
				for (const auto ref : refs) {
					if (symbols == nullptr) {
						bs << prefix << "     0x" << hex << ref << endl;
					} else {
						bs << prefix << "     ";
						auto ref_sym = Bean::dump_address(bs, ref, *symbols);
						if (ref_sym && ref_sym->id.valid()) {
							bs << ' ';
							ref_sym->id.dump(bs);
						}
						bs << endl;
					}
				}
		}

		if (rels.size() > 0) {
			bs << prefix << "  " << dec << rels.size() << " Relocation";
			if (rels.size() != 1)
				bs << 's';
			bs << endl;
			if (level >= TRACE)
				for (const auto & rel : rels) {
					bs << prefix << "     *0x" << hex << rel.offset << " = ";
					if (!rel.undefined)
						bs << "\e[3m";
					if (rel.name != 0) {
						bs << rel.name;
						if (rel.addend != 0)
							bs << " + " << dec << rel.addend;
					} else if (rel.target == 0) {
						bs << "0x" << hex << rel.addend;
					} else {
						auto ref_sym = Bean::dump_address(bs, rel.target, *symbols);
						if (ref_sym && ref_sym->id.valid()) {
							bs << ' ';
							ref_sym->id.dump(bs);
						}
					}
					if (!rel.undefined)
						bs << "\e[23m";
					bs << endl;
				}
		}

		if (deps.size() > 0) {
			bs << prefix << "  " << dec << deps.size() << " depending on this" << endl;
			if (level >= TRACE)
				for (const auto dep : deps) {
					if (symbols == nullptr) {
						bs << prefix << "     0x" << hex << dep << endl;
					} else {
						bs << prefix << "     ";
						auto ref_sym = Bean::dump_address(bs, dep, *symbols);
						if (ref_sym && ref_sym->id.valid()) {
							bs << ' ';
							ref_sym->id.dump(bs);
						}
						bs << endl;
					}
				}
		}

		if (id.valid()) {
			bs << prefix << "  \e[1mID: ";
			id.dump(bs);
			bs << "\e[22m" << endl;
		}

		bs << endl;
	}

}

void Bean::dump(BufferStream & bs, Verbosity level) const {
	auto foo = *symbols.highest();
	dump(bs, symbols, level);
}

void Bean::dump(BufferStream & bs, const symtree_t & symbols, Verbosity level) {
	Symbol::dump_header(bs, level);
	for (const auto & sym : symbols)
		sym.dump(bs, level, &symbols);
}
