#include <bean/bean.hpp>

#include "analyze.hpp"
#include "analyze_x86.hpp"
#include "capstone.hpp"


template<ELFCLASS C>
Bean::symtree_t analyze(const ELF<C> &elf, const ELF<C> * dbgsym, bool resolve_internal_relocations, bool debug, size_t buffer_size) {
	// Result
	Bean::symtree_t symbols;

	if (capstone_init()) {
		switch (elf.header.machine()) {
			case Elf::EM_386:
			case Elf::EM_486:
			case Elf::EM_X86_64:
				AnalyzeX86(symbols, elf, dbgsym, resolve_internal_relocations, debug, buffer_size).run();
				break;

			default:
				assert(false);
		}
	} else {
		// Init failed...
		assert(false);
	}

	return symbols;
}

Bean::SymbolRelocation::SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & relocation, bool resolve_target, uintptr_t global_offset_table)
  : offset(relocation.offset()), type(relocation.type()), name(nullptr), addend(relocation.addend()), target(0), undefined(false) {
	assert(relocation.valid());

	// Get relocation symbol
	if (relocation.symbol_index() != 0) {
		const auto rel_sym = relocation.symbol();
		name = rel_sym.name();
		undefined = (rel_sym.section_index() == ELF<ELF_Def::Identification::ELFCLASS32>::SHN_UNDEF);
	}

	if (!undefined)
		switch (relocation.type()) {
			case ELF<ELF_Def::Identification::ELFCLASS32>::R_X86_64_RELATIVE:
			case ELF<ELF_Def::Identification::ELFCLASS32>::R_X86_64_RELATIVE64:
				target = addend;
				break;

			default:
				// Perform relocation
				if (resolve_target)
					target = Relocator(relocation, global_offset_table).value(0);
		}
}

Bean::SymbolRelocation::SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & relocation, bool resolve_target, uintptr_t global_offset_table)
  : offset(relocation.offset()), type(relocation.type()), name(nullptr), addend(relocation.addend()), target(0), undefined(false) {
	assert(relocation.valid());

	// Get relocation symbol
	if (relocation.symbol_index() != 0) {
		const auto rel_sym = relocation.symbol();
		name = rel_sym.name();
		undefined = (rel_sym.section_index() == ELF<ELF_Def::Identification::ELFCLASS64>::SHN_UNDEF);
	}

	// Perform relocation
	if (!undefined)
		switch (relocation.type()) {
			case ELF<ELF_Def::Identification::ELFCLASS64>::R_X86_64_RELATIVE:
			case ELF<ELF_Def::Identification::ELFCLASS64>::R_X86_64_RELATIVE64:
				target = addend;
				break;

			default:
				// Perform relocation
				if (resolve_target)
					target = Relocator(relocation, global_offset_table).value(0);
		}
}


Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, const ELF<ELF_Def::Identification::ELFCLASS32> * dbgsym, bool resolve_internal_relocations, bool debug, size_t buffer_size) : symbols(analyze(elf, dbgsym, resolve_internal_relocations, debug, buffer_size)) {}

Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, const ELF<ELF_Def::Identification::ELFCLASS64> * dbgsym, bool resolve_internal_relocations, bool debug, size_t buffer_size) : symbols(analyze(elf, dbgsym, resolve_internal_relocations, debug, buffer_size)) {}

/*! \brief Merge memory areas */
const Bean::memarea_t Bean::merge(const symtree_t & symbols, size_t threshold) const {
	memarea_t area;
	for (const auto & sym : symbols) {
		if (!area.empty()) {
			auto & last = area.back();
			if (last.writeable == sym.section.writeable && last.executable == sym.section.executable && last.flags == sym.section.flags && last.address + last.size + threshold >= sym.address) {
				last.size = sym.address + sym.size - last.address;
				continue;
			}
		}
		area.emplace_back(sym.address, sym.size, sym.section.writeable, sym.section.executable, sym.section.flags);
	}
	return area;
}


bool Bean::patchable(const symhash_t & diff) {
	// TODO: Init sections
	uint16_t ignore = Symbol::Section::SECTION_RELRO | Symbol::Section::SECTION_EH_FRAME | Symbol::Section::SECTION_DYNAMIC;
	for (const auto & d : diff)
		if (d.section.writeable && (d.section.flags & ignore) == 0) {
			cerr << "A " << (void*)d.address << " " << d.size << "B " << d.name << endl;
			return false;
		} else if (d.section.has(Symbol::Section::SECTION_INIT)) {
			cerr << "B " << (void*)d.address << " " << d.size << "B " << d.name << endl;
			return false;
		}
	return true;
}
