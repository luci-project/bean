// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <bean/bean.hpp>

#include <dlh/is_in.hpp>
#include <dlh/string.hpp>
#include <dlh/xxhash.hpp>

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

uint64_t Bean::id_empty() {
	return XXHash64(id_hash_seed).hash();
}

const Bean::symtree_t Bean::diff(const Bean & other, bool include_dependencies, Bean::ComparisonMode mode) const {
	switch (mode) {
		case Bean::COMPARE_EXTENDED:
			return symtree_t(diff_extended(other, include_dependencies));

		case Bean::COMPARE_WRITEABLE_INTERNAL:
		 {
			syminthash_t i(other.symbols);
			symtree_t r;
			for (const auto & s : diff_extended(other, include_dependencies))
				if (!s.section.writeable || !i.contains(s))
					r.emplace(s);

			return r;
		 }

		case Bean::COMPARE_EXECUTABLE_EXTENDED:
		 {
			syminthash_t i(other.symbols);
			symtree_t r;
			for (const auto & s : diff_extended(other, include_dependencies))
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

TreeMap<uintptr_t, uintptr_t> Bean::map(const Bean & other, bool use_symbol_names) {
	// Mapping this -> other
	TreeMap<uintptr_t, uintptr_t> mapping;
	// Skip Symbols which are not unique
	HashSet<uintptr_t> skip;
	// skip non-unique internal id
	HashSet<uint64_t> skip_internal_id;

	auto insert_mapping = [&](uintptr_t from, uintptr_t to) {
		if (const auto map = mapping.find(from)) {
			// We have a match ...
			if (map->value != to) {
				// ... but it is ambiguous
				skip.insert(to);
				return false;
			}
		} else {
			auto from_sym = this->symbols.floor(from);
			auto to_sym = other.symbols.floor(to);
			// Address must be part of valid symbols
			if (!from_sym || !to_sym)
				return false;
			// Sections must be identical
			else if (!(from_sym->section == to_sym->section))
				return false;
			// Type must be identical
			else if (from_sym->type != Bean::Symbol::TYPE_UNKNOWN && to_sym->type != Bean::Symbol::TYPE_UNKNOWN && from_sym->type != to_sym->type)
				return false;
			mapping.insert(from, to);
		}
		return true;
	};

	auto process_relocations = [&](const Symbol & from, const Symbol & to) {
		if (!from.rels.empty() && from.rels.size() == to.rels.size()) {
			// Gather candidates by checking relocations
			const auto from_rel = from.rels.begin();
			const auto to_rel = to.rels.begin();
			for (; from_rel != from.rels.end(); ++from_rel, ++to_rel) {
				assert(to_rel != to.rels.end());
				if (!from_rel->undefined && !to_rel->undefined && (from_rel->offset - from.address) == (to_rel->offset - to.address) && from_rel->type == to_rel->type && from_rel->addend == to_rel->addend) {
					insert_mapping(from_rel->target, to_rel->target);
				}
			}
		}
	};

	// match entry and writable symbols
	 {
		size_t entries = 0;
		const Symbol * other_entry = nullptr;
		HashMap<Pair<const char *, uintptr_t>, const Symbol*> vars;
		for (const auto & sym : other.symbols)
			if (sym.has(Bean::Symbol::SYMBOL_ENTRY)) {
				other_entry = &sym;
				entries++;
			} else if (sym.section.writeable) {
				assert(TLS::virt_addr(sym.address) >= sym.section.address);
				vars.insert(Pair(sym.section.name, TLS::virt_addr(sym.address) - sym.section.address), &sym);
			}
		assert(entries <= 1);

		HashSet<uint64_t> internal_id;
		for (const auto & sym : this->symbols) {
			if (!internal_id.insert(sym.id.internal).second)
				skip_internal_id.insert(sym.id.internal);
			if (sym.has(Bean::Symbol::SYMBOL_ENTRY) && other_entry != nullptr) {
				assert(other_entry->type == sym.type && other_entry->bind == sym.bind && other_entry->section == sym.section);
				insert_mapping(sym.address, other_entry->address);
			} else if (sym.section.writeable) {
				if (auto var = vars.find(Pair(sym.section.name, TLS::virt_addr(sym.address) - sym.section.address))) {
					// Must match in offset and size
					if ((sym.address % 0x1000) == (var->value->address % 0x1000) && sym.size == var->value->size)
						insert_mapping(sym.address, var->value->address);
				}
			}
		}
	 }

	// match named symbols (having identical section)
	if (use_symbol_names) {
		Symbol * other_entry = nullptr;
		HashMap<const char *, const Symbol*> names;
		for (const auto & sym : other.symbols) {
			if (String::len(sym.name) > 0)
				names.insert(sym.name, &sym);
		}

		for (const auto & sym : this->symbols) {
			if (auto has_mapping = mapping.find(sym.address))
				continue;
			if (String::len(sym.name) == 0)
				continue;
			auto other_sym = names.find(sym.name);
			if (other_sym && other_sym->value->type == sym.type && other_sym->value->bind == sym.bind && other_sym->value->section == sym.section)
				insert_mapping(sym.address, other_sym->value->address);
		}
	}

	// match full equal IDs and their relocations
	 {
		const symhash_t other_symbols(other.symbols);
		for (const auto & sym : this->symbols) {
			if (const auto other_sym = other_symbols.find(sym)) {
				insert_mapping(sym.address, other_sym->address);
				process_relocations(sym, *other_sym);
			}
		}
	 }

	// afterwards check relocations of functions with identical internal ID (and type, bind + section)
	 {
		const syminthash_t other_symbols(other.symbols);
		for (const auto & sym : this->symbols)
			if (skip_internal_id.contains(sym.id.internal))
				continue;
			else if (const auto other_sym = other_symbols.find(sym))
				process_relocations(sym, *other_sym);
	 }

	// TODO: Update relocations only if internal ID is identical!

	// Cleanup
	for (const auto address : skip)
		mapping.erase(address);

	return mapping;
}

Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, const ELF<ELF_Def::Identification::ELFCLASS32> * dbgsym, uint32_t flags) : symbols(analyze(elf, dbgsym, flags)) {}

Bean::Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, const ELF<ELF_Def::Identification::ELFCLASS64> * dbgsym, uint32_t flags) : symbols(analyze(elf, dbgsym, flags)) {}
