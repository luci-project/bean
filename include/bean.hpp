#pragma once

#include <cstdio>

#include <algorithm>
#include <unordered_set>
#include <map>
#include <vector>

#include <capstone/capstone.h>
#include "elf.hpp"
#include "xxhash64.h"

struct Bean {
	struct Symbol {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Symbol name (for debugging) */
		const char * name;

		// ToDo: Version?

		/*! \brief Identifier based on instructions (without refs) */
		uint64_t id;

		/*! \brief Refs identifier */
		uint64_t id_ref;

		/*! \brief Symbol ids using this symbol */
		std::unordered_set<uintptr_t> deps;

		/*! \brief Reference of used symbols */
		std::vector<uintptr_t> refs;

		/*! \brief Do unresolved references exist? */
		bool refs_unresolved;

		Symbol(uintptr_t address, size_t size, const char * name = nullptr) : address(address), size(size), name(name), id(0), id_ref(0), refs_unresolved(false) {}

		void merge(uintptr_t address, size_t size, const char * name = nullptr) {
			if (address < this->address)
				this->address = address;
			this->size = std::max(this->address + this->size, address + size) - this->address;
			if (this->name == nullptr)
				this->name = name;
			this->id = 0;
		}

		void merge(const Symbol & other) {
			merge(other.address, other.size, other.name);
			if (other.refs.size() > 0)
				refs.insert(refs.end(), other.refs.begin(), other.refs.end());
		}

		void ref(uintptr_t to) {
			if (to < address || to >= address + size)
				refs.push_back(to);
		}

		static void dump_header() {
			printf("ID               ID refs          [Ref / Dep] - Address             Size  Name\n");
		}

		void dump(bool verbose = false) const {
			if (verbose)
				//printf("%016lx %016lx [%3lu / %3lu] - 0x%016lx %6lu %s\n", id, id_ref, refs.size(), deps.size(), address, size, name);
				printf("%016lx %016lx [%3lu / %3lu] - 0x%016lx %6lu %s\n", id, id_ref, refs.size(), deps.size(), address, size, name);
			else
				printf("%016lx %016lx\n", id, id_ref);
		}

		bool operator==(const Symbol & that) const {
			return this->id == that.id && this->id_ref == that.id_ref && this->refs.size() == that.refs.size() && this->deps.size() == that.deps.size();
		}
	};

	class SymbolHash {
	 public:
		size_t operator()(const Symbol& sym) const {
			return sym.id ^ sym.id_ref;
		}
	};

	typedef std::unordered_set<Symbol, SymbolHash> symbols_t;

	const Elf & elf;
	const std::map<uintptr_t, Symbol> symbols;

	Bean(const Elf & elf) : elf(elf), symbols(analyze(elf)) {}

	void dump(bool verbose = false) const {
		if (verbose)
			Symbol::dump_header();
		for (auto & symbol_node : symbols)
			symbol_node.second.dump(verbose);
	}

	static void dump(const symbols_t & symbols, bool verbose = false) {
		if (verbose)
			Symbol::dump_header();
		for (auto & sym: symbols)
			sym.dump(verbose);
	}

	const symbols_t hashset() const {
		symbols_t symbolset;
		for (auto & symbol_node : symbols) {
			auto & sym = symbol_node.second;
			symbolset.insert(sym);
		}
		return symbolset;
	}

	const symbols_t diff(const symbols_t & other_symbols, bool include_dependencies = false) const {
		symbols_t result;
		for (const auto & symbol_node : symbols) {
			auto & sym = symbol_node.second;
			if (other_symbols.count(sym) == 0 && result.insert(sym).second && include_dependencies)
				for (const auto d: sym.deps)
					dependencies(d, result);
		}
		return result;
	}

	const symbols_t diff(const Bean & other, bool include_dependencies = false) const {
		return diff(other.hashset(), include_dependencies);
	}

 private:
	void dependencies(uintptr_t address, symbols_t & result) const {
		auto sym = symbols.lower_bound(~address);
		if (sym != symbols.end() && result.insert(sym->second).second)
			for (const auto d: sym->second.deps)
				dependencies(d, result);
	}

	static bool branch_relative(unsigned int instruction) {
		switch (instruction) {
			case X86_INS_JAE:
			case X86_INS_JA:
			case X86_INS_JBE:
			case X86_INS_JB:
			case X86_INS_JCXZ:
			case X86_INS_JECXZ:
			case X86_INS_JE:
			case X86_INS_JGE:
			case X86_INS_JG:
			case X86_INS_JLE:
			case X86_INS_JL:
			case X86_INS_JMP:
			case X86_INS_JNE:
			case X86_INS_JNO:
			case X86_INS_JNP:
			case X86_INS_JNS:
			case X86_INS_JO:
			case X86_INS_JP:
			case X86_INS_JRCXZ:
			case X86_INS_JS:

			case X86_INS_CALL:

			case X86_INS_LOOP:
			case X86_INS_LOOPE:
			case X86_INS_LOOPNE:

			case X86_INS_XBEGIN:
				return true;

			default:
				return false;
		}
	}

	static void insert(std::map<uintptr_t, Symbol> & symbols, uintptr_t address, size_t size = 0, const char * name = nullptr) {
		auto pos = symbols.find(~address);
		if (pos == symbols.end())
			symbols.emplace_hint(pos, ~address, Symbol{address, size, name});
		else
			pos->second.merge(address, size, name);
	}
/*
	void merge(std::map<uintptr_t, Symbol>::iterator & pos, uintptr_t address, size_t size = 0, const char * name = nullptr) {
		if (pos == symbols.end()) {
			symbols.emplace_hint(pos, ~address, Symbol{address, size, name});
		} else if (address < pos->second.address) {
			auto sym = symbols.extract(pos);
			sym.mapped().merge(address, size, name);
			sym.key() = ~address;
			symbols.insert(std::move(sym));
		} else {
			pos->second.merge(address, size, name);
		}
	}
*/

	static std::map<uintptr_t, Symbol> analyze(const Elf &elf) {
		std::map<uintptr_t, Symbol> symbols;
		std::map<uintptr_t, Elf::Section> sections;

		// 1. Read symbols and segments
		for (const auto & section: elf.sections) {
			if (section.allocate())
				sections.insert(std::make_pair(~section.virt_addr(), section));
			switch(section.type()) {
				// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
				case Elf::SHT_REL:
					// TODO: relocations<typename Elf::Relocation>(section);
					break;
				case Elf::SHT_RELA:
					// TODO: relocations<typename Elf::RelocationWithAddend>(section);
					break;

				case Elf::SHT_SYMTAB:
				case Elf::SHT_DYNSYM:
					for (auto & sym: section.get_symbols())
						switch (sym.section_index()) {
							case Elf::SHN_UNDEF:
							case Elf::SHN_ABS:
							case Elf::SHN_COMMON:
							case Elf::SHN_XINDEX:
								break;

							default:
								assert(sym.value() >= elf.sections[sym.section_index()].virt_addr());
								assert(sym.value() + sym.size() <= elf.sections[sym.section_index()].virt_addr() + elf.sections[sym.section_index()].size());
								if (sym.value() != 0 && elf.sections[sym.section_index()].allocate())
									insert(symbols, sym.value(), sym.size(), sym.name());
						}
					break;

				default:
					continue;
			}
		}
		// Prepare disassembly
		csh cshandle;
		if (::cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) // todo: depending on ELF
			return {};
		::cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);

		cs_insn *insn = cs_malloc(cshandle);

		// 2. Gather (additional) function start addresses by reading call-targets
		//    if call target exists (from symtab)-> ignore
		for (const auto & section_node : sections) {
			const auto & section = section_node.second;
			if (section.executable()) {
				const auto index = elf.sections.index(section);
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data());
				uintptr_t address = section.virt_addr();
				insert(symbols, address, 0, section.name());

				size_t size = section.size();
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					for (size_t g = 0; g < insn->detail->groups_count; g++) {
						if (insn->detail->groups[g] == CS_GRP_CALL) {
							auto & detail_x86 = insn->detail->x86;
							auto & op = detail_x86.operands[detail_x86.op_count - 1];
							if (op.type == X86_OP_IMM)
								insert(symbols, op.imm);
							else if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
								// Ignore segment, index, scale
								insert(symbols, insn->address + insn->size + op.mem.disp);
							}
						}
					}
				}
			}
		}

		// 3. Disassemble again...
		size_t last_addr = SIZE_MAX;
		for (auto & symbol_node : symbols) {
			auto & sym = symbol_node.second;
			const auto section_node = sections.lower_bound(symbol_node.first);
			assert(section_node != sections.end());
			const auto & section = section_node->second;

			// 3a. calculate size (if 0), TODO: ignore nops!
			const size_t max_addr = std::min(last_addr, section.virt_addr() + section.size());
			uintptr_t address = sym.address;
			assert(max_addr >= address);
			const size_t max_size = max_addr - address;
			if (max_size > sym.size)
				sym.size = max_size;

			// 3b. generate links (from jmp + call) & hash
			const size_t offset = address - section.virt_addr();
			const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data()) + offset;
			XXHash64 id(0);  // TODO seed
			if (section.executable()) {
				size_t size = sym.size;
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					auto & detail_x86 = insn->detail->x86;
					// Prefix, opcode, rex, addr_size, modrm, sib
					id.add(&(detail_x86), 12);
					// TODO: Relocations
					for (int o = 0; o < detail_x86.op_count; o++) {
						auto & op = detail_x86.operands[o];
						switch (op.type) {
							case X86_OP_REG:
								id.add(&(op.reg), sizeof(x86_reg));
								break;
							case X86_OP_IMM:
								if (branch_relative(insn->id))
									sym.ref(op.imm);
								else
									id.add(&(op.imm), sizeof(int64_t));
								break;
							case X86_OP_MEM:
								if (op.mem.base == X86_REG_RIP) {
									sym.ref(insn->address + insn->size + op.mem.disp);
								} else {
									// unresolved?
									id.add(&(op.mem), sizeof(x86_op_mem));
								}
								break;
						}
					}
				}
			} else {
				// Non-executable objects will be fully hashed
				// TODO: Relocations
				id.add(data, sym.size);
			}

			sym.id = id.hash();

			last_addr = sym.address;
		}
		cs_free(insn, 1);

		// 4. Calculate full id, set dependencies and add to final set
		for (auto & symbol_node : symbols) {
			auto & sym = symbol_node.second;

			if (sym.refs.size() > 0) {
				XXHash64 id_ref(0);  // TODO seed
				for (const auto ref : sym.refs) {
					auto ref_sym = symbols.lower_bound(~ref);
					if (ref_sym != symbols.end()) {
						// Hash ID and offset
						const uint64_t r[2] = { ref_sym->second.id, ref - ref_sym->second.address};
						id_ref.add(r, 2 * sizeof(uint64_t));
						ref_sym->second.deps.insert(sym.address);
					} else {
						// TODO
					}
				}
				sym.id_ref = id_ref.hash();
			}
		}

		return symbols;
	}
};
