#include <bean/bean.hpp>

#include <dlh/is_in.hpp>

#include "analyze.hpp"
#include "analyze_x86.hpp"
#include "capstone.hpp"


template<ELFCLASS C>
static Bean::symtree_t analyze(const ELF<C> &elf, const ELF<C> * dbgsym, uint32_t flags) {
	// Result
	Bean::symtree_t symbols;

	if (capstone_init()) {
		switch (elf.header.machine()) {
			case Elf::EM_386:
			case Elf::EM_486:
			case Elf::EM_X86_64:
				AnalyzeX86(symbols, elf, dbgsym, flags).run();
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

Bean::SymbolRelocation::SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & relocation, ELF_Def::Constants::ehdr_machine machine, bool resolve_target, uintptr_t global_offset_table)
  : offset(relocation.offset()), type(relocation.type()), name(nullptr), addend(relocation.addend()), target(0), machine(machine), undefined(false), reconstructed(false) {
	assert(relocation.valid());

	// Get relocation symbol
	if (relocation.symbol_index() != 0) {
		const auto rel_sym = relocation.symbol();
		name = rel_sym.name();
		undefined = (rel_sym.section_index() == ELF<ELF_Def::Identification::ELFCLASS32>::SHN_UNDEF);
	}

	if (!undefined) {
		if (is(machine).in(Elf::EM_386, Elf::EM_486) && relocation.type() == ELF<ELF_Def::Identification::ELFCLASS64>::R_386_RELATIVE)
			target = addend;
		else if (resolve_target)
			target = Relocator(relocation, global_offset_table).value(0);
	}
}

Bean::SymbolRelocation::SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & relocation, ELF_Def::Constants::ehdr_machine machine, bool resolve_target, uintptr_t global_offset_table)
  : offset(relocation.offset()), type(relocation.type()), name(nullptr), addend(relocation.addend()), target(0), machine(machine), undefined(false), reconstructed(false) {
	assert(relocation.valid());

	// Get relocation symbol
	if (relocation.symbol_index() != 0) {
		const auto rel_sym = relocation.symbol();
		name = rel_sym.name();
		undefined = (rel_sym.section_index() == ELF<ELF_Def::Identification::ELFCLASS64>::SHN_UNDEF);
	}

	// Perform relocation
	if (!undefined) {
		if (machine == Elf::EM_X86_64 && is(relocation.type()).in(ELF<ELF_Def::Identification::ELFCLASS64>::R_X86_64_RELATIVE, ELF<ELF_Def::Identification::ELFCLASS64>::R_X86_64_RELATIVE64))
			target = addend;
		else if (resolve_target)
			target = Relocator(relocation, global_offset_table).value(0);
	}
}

bool Bean::diet() {
#ifdef BEAN_VERBOSE
	return false;
#else
	return true;
#endif
}

const Bean::symtree_t Bean::diff(const Bean & other, bool include_dependencies, Bean::ComparisonMode mode) const {
	switch (mode) {
		case Bean::COMPARE_EXTENDED:
			return symtree_t(diff_extended(other, include_dependencies));

		case Bean::COMPARE_WRITEABLE_INTERNAL:
		{
			syminthash_t i(other.symbols);
			symtree_t r;
			for (auto & s : diff_extended(other, include_dependencies))
				if (!s.section.writeable || !i.contains(s))
					r.emplace(s);

			return r;
		}

		case Bean::COMPARE_EXECUTABLE_EXTENDED:
		{
			syminthash_t i(other.symbols);
			symtree_t r;
			for (auto & s : diff_extended(other, include_dependencies))
				if (s.section.executable || !i.contains(s))
					r.emplace(s);

			return r;
		}

		case Bean::COMPARE_ONLY_INTERNAL:
			return symtree_t(diff_internal(other, include_dependencies));

		default:
			assert(false);
			return symtree_t();
	}
}

Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, const ELF<ELF_Def::Identification::ELFCLASS32> * dbgsym, uint32_t flags) : symbols(analyze(elf, dbgsym, flags)) {}

Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, const ELF<ELF_Def::Identification::ELFCLASS64> * dbgsym, uint32_t flags) : symbols(analyze(elf, dbgsym, flags)) {}
