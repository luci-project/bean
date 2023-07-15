// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <bean/bean.hpp>
static bool dump_relocation(BufferStream & bs, uintptr_t type, ELF_Def::Constants::ehdr_machine machine) {
	switch (machine) {
	case Elf::EM_386:
	case Elf::EM_486:
		switch (type) {
		case ELF_Def::Constants::R_386_NONE:
			bs << "R_386_NONE";
			return true;
		case ELF_Def::Constants::R_386_32:
			bs << "R_386_32";
			return true;
		case ELF_Def::Constants::R_386_PC32:
			bs << "R_386_PC32";
			return true;
		case ELF_Def::Constants::R_386_GOT32:
			bs << "R_386_GOT32";
			return true;
		case ELF_Def::Constants::R_386_PLT32:
			bs << "R_386_PLT32";
			return true;
		case ELF_Def::Constants::R_386_COPY:
			bs << "R_386_COPY";
			return true;
		case ELF_Def::Constants::R_386_GLOB_DAT:
			bs << "R_386_GLOB_DAT";
			return true;
		case ELF_Def::Constants::R_386_JMP_SLOT:
			bs << "R_386_JMP_SLOT";
			return true;
		case ELF_Def::Constants::R_386_RELATIVE:
			bs << "R_386_RELATIVE";
			return true;
		case ELF_Def::Constants::R_386_GOTOFF:
			bs << "R_386_GOTOFF";
			return true;
		case ELF_Def::Constants::R_386_GOTPC:
			bs << "R_386_GOTPC";
			return true;
		case ELF_Def::Constants::R_386_32PLT:
			bs << "R_386_32PLT";
			return true;
		case ELF_Def::Constants::R_386_TLS_TPOFF:
			bs << "R_386_TLS_TPOFF";
			return true;
		case ELF_Def::Constants::R_386_TLS_IE:
			bs << "R_386_TLS_IE";
			return true;
		case ELF_Def::Constants::R_386_TLS_GOTIE:
			bs << "R_386_TLS_GOTIE";
			return true;
		case ELF_Def::Constants::R_386_TLS_LE:
			bs << "R_386_TLS_LE";
			return true;
		case ELF_Def::Constants::R_386_TLS_GD:
			bs << "R_386_TLS_GD";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDM:
			bs << "R_386_TLS_LDM";
			return true;
		case ELF_Def::Constants::R_386_16:
			bs << "R_386_16";
			return true;
		case ELF_Def::Constants::R_386_PC16:
			bs << "R_386_PC16";
			return true;
		case ELF_Def::Constants::R_386_8:
			bs << "R_386_8";
			return true;
		case ELF_Def::Constants::R_386_PC8:
			bs << "R_386_PC8";
			return true;
		case ELF_Def::Constants::R_386_TLS_GD_32:
			bs << "R_386_TLS_GD_32";
			return true;
		case ELF_Def::Constants::R_386_TLS_GD_PUSH:
			bs << "R_386_TLS_GD_PUSH";
			return true;
		case ELF_Def::Constants::R_386_TLS_GD_CALL:
			bs << "R_386_TLS_GD_CALL";
			return true;
		case ELF_Def::Constants::R_386_TLS_GD_POP:
			bs << "R_386_TLS_GD_POP";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDM_32:
			bs << "R_386_TLS_LDM_32";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDM_PUSH:
			bs << "R_386_TLS_LDM_PUSH";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDM_CALL:
			bs << "R_386_TLS_LDM_CALL";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDM_POP:
			bs << "R_386_TLS_LDM_POP";
			return true;
		case ELF_Def::Constants::R_386_TLS_LDO_32:
			bs << "R_386_TLS_LDO_32";
			return true;
		case ELF_Def::Constants::R_386_TLS_IE_32:
			bs << "R_386_TLS_IE_32";
			return true;
		case ELF_Def::Constants::R_386_TLS_LE_32:
			bs << "R_386_TLS_LE_32";
			return true;
		case ELF_Def::Constants::R_386_TLS_DTPMOD32:
			bs << "R_386_TLS_DTPMOD32";
			return true;
		case ELF_Def::Constants::R_386_TLS_DTPOFF32:
			bs << "R_386_TLS_DTPOFF32";
			return true;
		case ELF_Def::Constants::R_386_TLS_TPOFF32:
			bs << "R_386_TLS_TPOFF32";
			return true;
		case ELF_Def::Constants::R_386_SIZE32:
			bs << "R_386_SIZE32";
			return true;
		case ELF_Def::Constants::R_386_TLS_GOTDESC:
			bs << "R_386_TLS_GOTDESC";
			return true;
		case ELF_Def::Constants::R_386_TLS_DESC_CALL:
			bs << "R_386_TLS_DESC_CALL";
			return true;
		case ELF_Def::Constants::R_386_TLS_DESC:
			bs << "R_386_TLS_DESC";
			return true;
		case ELF_Def::Constants::R_386_IRELATIVE:
			bs << "R_386_IRELATIVE";
			return true;
		case ELF_Def::Constants::R_386_GOT32X:
			bs << "R_386_GOT32X";
			return true;
		default:
			return false;
		}

	case Elf::EM_X86_64:
		switch (type) {
		case ELF_Def::Constants::R_X86_64_NONE:
			bs << "R_X86_64_NONE";
			return true;
		case ELF_Def::Constants::R_X86_64_64:
			bs << "R_X86_64_64";
			return true;
		case ELF_Def::Constants::R_X86_64_PC32:
			bs << "R_X86_64_PC32";
			return true;
		case ELF_Def::Constants::R_X86_64_GOT32:
			bs << "R_X86_64_GOT32";
			return true;
		case ELF_Def::Constants::R_X86_64_PLT32:
			bs << "R_X86_64_PLT32";
			return true;
		case ELF_Def::Constants::R_X86_64_COPY:
			bs << "R_X86_64_COPY";
			return true;
		case ELF_Def::Constants::R_X86_64_GLOB_DAT:
			bs << "R_X86_64_GLOB_DAT";
			return true;
		case ELF_Def::Constants::R_X86_64_JUMP_SLOT:
			bs << "R_X86_64_JUMP_SLOT";
			return true;
		case ELF_Def::Constants::R_X86_64_RELATIVE:
			bs << "R_X86_64_RELATIVE";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPCREL:
			bs << "R_X86_64_GOTPCREL";
			return true;
		case ELF_Def::Constants::R_X86_64_32:
			bs << "R_X86_64_32";
			return true;
		case ELF_Def::Constants::R_X86_64_32S:
			bs << "R_X86_64_32S";
			return true;
		case ELF_Def::Constants::R_X86_64_16:
			bs << "R_X86_64_16";
			return true;
		case ELF_Def::Constants::R_X86_64_PC16:
			bs << "R_X86_64_PC16";
			return true;
		case ELF_Def::Constants::R_X86_64_8:
			bs << "R_X86_64_8";
			return true;
		case ELF_Def::Constants::R_X86_64_PC8:
			bs << "R_X86_64_PC8";
			return true;
		case ELF_Def::Constants::R_X86_64_DTPMOD64:
			bs << "R_X86_64_DTPMOD64";
			return true;
		case ELF_Def::Constants::R_X86_64_DTPOFF64:
			bs << "R_X86_64_DTPOFF64";
			return true;
		case ELF_Def::Constants::R_X86_64_TPOFF64:
			bs << "R_X86_64_TPOFF64";
			return true;
		case ELF_Def::Constants::R_X86_64_TLSGD:
			bs << "R_X86_64_TLSGD";
			return true;
		case ELF_Def::Constants::R_X86_64_TLSLD:
			bs << "R_X86_64_TLSLD";
			return true;
		case ELF_Def::Constants::R_X86_64_DTPOFF32:
			bs << "R_X86_64_DTPOFF32";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTTPOFF:
			bs << "R_X86_64_GOTTPOFF";
			return true;
		case ELF_Def::Constants::R_X86_64_TPOFF32:
			bs << "R_X86_64_TPOFF32";
			return true;
		case ELF_Def::Constants::R_X86_64_PC64:
			bs << "R_X86_64_PC64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTOFF64:
			bs << "R_X86_64_GOTOFF64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPC32:
			bs << "R_X86_64_GOTPC32";
			return true;
		case ELF_Def::Constants::R_X86_64_GOT64:
			bs << "R_X86_64_GOT64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPCREL64:
			bs << "R_X86_64_GOTPCREL64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPC64:
			bs << "R_X86_64_GOTPC64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPLT64:
			bs << "R_X86_64_GOTPLT64";
			return true;
		case ELF_Def::Constants::R_X86_64_PLTOFF64:
			bs << "R_X86_64_PLTOFF64";
			return true;
		case ELF_Def::Constants::R_X86_64_SIZE32:
			bs << "R_X86_64_SIZE32";
			return true;
		case ELF_Def::Constants::R_X86_64_SIZE64:
			bs << "R_X86_64_SIZE64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPC32_TLSDESC:
			bs << "R_X86_64_GOTPC32_TLSDESC";
			return true;
		case ELF_Def::Constants::R_X86_64_TLSDESC_CALL:
			bs << "R_X86_64_TLSDESC_CALL";
			return true;
		case ELF_Def::Constants::R_X86_64_TLSDESC:
			bs << "R_X86_64_TLSDESC";
			return true;
		case ELF_Def::Constants::R_X86_64_IRELATIVE:
			bs << "R_X86_64_IRELATIVE";
			return true;
		case ELF_Def::Constants::R_X86_64_RELATIVE64:
			bs << "R_X86_64_RELATIVE64";
			return true;
		case ELF_Def::Constants::R_X86_64_GOTPCRELX:
			bs << "R_X86_64_GOTPCRELX";
			return true;
		case ELF_Def::Constants::R_X86_64_REX_GOTPCRELX:
			bs << "R_X86_64_REX_GOTPCRELX";
			return true;
		case ELF_Def::Constants::R_X86_64_GNU_VTINHERIT:
			bs << "R_X86_64_GNU_VTINHERIT";
			return true;
		case ELF_Def::Constants::R_X86_64_GNU_VTENTRY:
			bs << "R_X86_64_GNU_VTENTRY";
			return true;
		default:
			return false;
		}

	default:
		return false;
	}
}

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
		if (ref_sym->name != nullptr) {
			bs << ref_sym->name;
		} else {
			if (TLS::is_tls(ref_sym->address))
				bs << "TLS:";
			bs << "0x" << hex << TLS::virt_addr(ref_sym->address);
		}

		if (ref_sym->section.name != nullptr)
			bs << '/' << ref_sym->section.name;

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
		if (debug != nullptr || !refs.empty() || !rels.empty() || !deps.empty())
			bs << ':';
		bs << endl;

		if (debug != nullptr) {
			size_t i = 0;
			size_t s = 0;
			do {
				for (i = s; debug[i] != '\0' && debug[i] != '\n'; i++) {}
				if (i > s) {
					bs << prefix;
					bs.write(debug + s, i - s + 1);
					s = i + 1;
				}
			} while (debug[i] != '\0');
		}
#endif
		if (!refs.empty()) {
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

		if (!rels.empty()) {
			bs << prefix << "  " << dec << rels.size() << " Relocation";
			if (rels.size() != 1)
				bs << 's';
			bs << endl;
			if (level >= TRACE)
				for (const auto & rel : rels) {
					bs << prefix << "     ";
					if (rel.reconstructed)
						bs << "\e[3m";
					bs << "*0x" << hex << rel.offset;
					if (rel.reconstructed)
						bs << "\e[23m";
					bs << " = \e[2m";
					if (!dump_relocation(bs, rel.type, rel.machine))
						bs << '[' << static_cast<unsigned short>(rel.machine) << ':' << rel.type << ']' << endl;
					bs << "\e[22m ";
					if (!rel.undefined)
						bs << "\e[3m";
					if (rel.name != 0) {
						bs << rel.name;
						if (rel.addend != 0)
							bs.format(" %+ ld", rel.addend);
					} else if (rel.target == 0) {
						bs << "0x" << hex << rel.addend;
					} else {
						auto ref_sym = Bean::dump_address(bs, rel.target, *symbols);
						if (ref_sym && ref_sym->id.valid()) {
							bs << ' ';
							ref_sym->id.dump(bs);
						}
					}
					if (rel.instruction_access != Bean::SymbolRelocation::ACCESSFLAG_UNKNOWN) {
						bs << " \e[2m(";
						if ((rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_READ) != 0)
							bs << 'r';
						if ((rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_WRITE) != 0)
							bs << 'w';
						if ((rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_BRANCH) != 0)
							bs << 'b';
						if ((rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_LOCAL) != 0)
							bs << 'l';
						bs << '@-' << static_cast<unsigned>(rel.instruction_offset) << ") \e[22m";
					}
					if (!rel.undefined)
						bs << "\e[23m";
					bs << endl;
				}
		}

		if (!deps.empty()) {
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
