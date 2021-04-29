#pragma once

#include <cstdio>
#include <cstring>

#include <algorithm>
#include <unordered_set>
#include <set>
#include <vector>

#include <capstone/capstone.h>
#include "elf.hpp"
#include "elf_rel.hpp"
#include "xxhash64.h"

struct Bean {
	struct Symbol {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		mutable size_t size;

		/*! \brief Symbol name (for debugging) */
		mutable const char * name;

		/*! \brief Identifier based on instructions (without refs) */
		mutable uint64_t id;

		/*! \brief Refs identifier */
		mutable uint64_t id_ref;

		/*! \brief Symbol ids using this symbol
		 * \note vector (instead of unordered_set) due to performance
		 */
		mutable std::vector<uintptr_t> deps;

		/*! \brief Reference of used symbols */
		mutable std::vector<uintptr_t> refs;

		Symbol(uintptr_t address, size_t size, const char * name = nullptr) : address(address), size(size), name(name), id(0), id_ref(0) {}

		void ref(uintptr_t to) const {
			// only external references
			if (to < address || to >= address + size)
				refs.push_back(to);
		}

		bool dep(uintptr_t from) const {
			// only add once
			if (std::find(deps.begin(), deps.end(), from) == deps.end()) {
				deps.push_back(from);
				return true;
			} else {
				return false;
			}
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

	struct SymbolSort {
		using is_transparent = void;

		bool operator()(const Symbol & lhs, const Symbol & rhs) const { return lhs.address > rhs.address; }
		bool operator()(uintptr_t lhs, const Symbol & rhs) const { return lhs > rhs.address; }
		bool operator()(const Symbol & lhs, uintptr_t rhs) const { return lhs.address > rhs; }

		bool operator()(const Elf::Section & lhs, const Elf::Section & rhs) const { return lhs.virt_addr() > rhs.virt_addr(); }
		bool operator()(const Symbol & lhs, const Elf::Section & rhs) const { return lhs.address > rhs.virt_addr(); }
		bool operator()(const Elf::Section & lhs, const Symbol & rhs) const { return lhs.virt_addr() > rhs.address; }

		bool operator()(const Elf::Relocation & lhs, const Elf::Relocation & rhs) const { return lhs.offset() > rhs.offset(); }
		bool operator()(const Symbol & lhs, const Elf::Relocation & rhs) const { return lhs.address > rhs.offset(); }
		bool operator()(const Elf::Relocation & lhs, const Symbol & rhs) const { return lhs.offset() > rhs.address; }
		bool operator()(uintptr_t lhs, const Elf::Relocation & rhs) const { return lhs > rhs.offset(); }
		bool operator()(const Elf::Relocation & lhs, uintptr_t rhs) const { return lhs.offset() > rhs; }
	};

	class SymbolHash {
	 public:
		size_t operator()(const Symbol& sym) const {
			return sym.id ^ sym.id_ref;
		}
	};

	typedef std::unordered_set<Symbol, SymbolHash> symhash_t;
	typedef std::set<Symbol, SymbolSort> symsort_t;
	typedef std::vector<std::pair<uintptr_t, size_t>> memarea_t;

	const Elf & elf;
	const symsort_t symbols;

	Bean(const Elf & elf, bool resolve_relocations = true, bool explain = false) : elf(elf), symbols(analyze(elf, resolve_relocations, explain)) {}

	void dump(bool verbose = false) const {
		dump(symbols, verbose);
	}

	static void dump(const symsort_t & symbols, bool verbose = false) {
		if (verbose)
			Symbol::dump_header();
		for (auto it = symbols.rbegin(); it != symbols.rend(); ++it)
			it->dump(verbose);
	}

	static void dump(const symhash_t & symbols, bool verbose = false) {
		if (verbose) {
			// Sort output by address
			dump(symsort_t(symbols.begin(), symbols.end()), verbose);
		} else {
			// unsorted
			for (auto & sym: symbols)
				sym.dump(verbose);
		}
	}

	/*! \brief Merge memory areas */
	const memarea_t merge(const symsort_t & symbols, size_t threshold = 0) const {
		memarea_t area;
		for (auto it = symbols.rbegin(); it != symbols.rend(); ++it) {
			if (!area.empty()) {
				const auto & address = area.back().first;
				auto & size = area.back().second;
				if (address + size + threshold >= it->address) {
					size = it->address + it->size - address;
					continue;
				}
			}
			area.emplace_back(it->address, it->size);
		}
		return area;
	}

	/*! \brief Merge memory areas
	 * \note ids and names will be removed
	 */
	const memarea_t merge(const symhash_t & symbols, size_t threshold = 0) const {
		return merge(symsort_t(symbols.begin(), symbols.end()), threshold);
	}

	const memarea_t diffmerge(const symhash_t & other_symbols, bool include_dependencies = false, size_t threshold = 0) const {
		return merge(diff(other_symbols, include_dependencies), threshold);
	}

	const memarea_t diffmerge(const Bean & other, bool include_dependencies = false, size_t threshold = 0) const {
		return merge(diff(other, include_dependencies), threshold);
	}

	const symhash_t diff(const symhash_t & other_symbols, bool include_dependencies = false) const {
		symhash_t result;
		for (const auto & sym : symbols)
			if (other_symbols.count(sym) == 0 && result.insert(sym).second && include_dependencies)
				for (const auto d: sym.deps)
					dependencies(d, result);
		return result;
	}

	const symhash_t diff(const Bean & other, bool include_dependencies = false) const {
		return diff(symhash_t(other.symbols.begin(), other.symbols.end()), include_dependencies);
	}

	const Symbol * get(uintptr_t address)  const  {
		auto sym = symbols.lower_bound(address);
		return sym != symbols.end() && address < sym->address + sym->size ? &(*sym) : nullptr;
	}

	auto find(uintptr_t address = 0) const {
		return std::make_reverse_iterator(symbols.upper_bound(address));
	}

	auto begin() const {
		return symbols.rbegin();
	}

	auto end() const {
		return symbols.rend();
	}

 private:
	template<int SIZE>
	struct ByteBuffer {
		uint8_t buffer[SIZE];
		size_t size;

		ByteBuffer() : size(0) {}

		template<typename T>
		size_t push(const T & v) {
			assert(size + sizeof(T) < SIZE);
			*reinterpret_cast<T *>(buffer + size) = v;
			size += sizeof(T);
			return sizeof(T);
		}

		void clear() {
			size = 0;
		}
	};

	void dependencies(uintptr_t address, symhash_t & result) const {
		auto sym = symbols.lower_bound(address);
		if (sym != symbols.end() && result.insert(*sym).second)
			for (const auto d: sym->deps)
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

	static void insert_symbol(symsort_t & symbols, uintptr_t address, size_t size = 0, const char * name = nullptr) {
		auto pos = symbols.find(address);
		if (pos == symbols.end()) {
			symbols.insert(Symbol{address, size, name});
		} else {
			const auto max_address = std::max(pos->address + pos->size, address + size);
			bool new_name = name != nullptr &&  (pos->name == nullptr || pos->name[0] == '\0');
			if (address < pos->address) {
				auto sym = symbols.extract(pos);
				sym.value().address = address;
				sym.value().size = max_address - address;
				if (new_name)
					sym.value().name = name;
				symbols.insert(std::move(sym));
			} else {
				pos->size = max_address - pos->address;
				if (new_name)
					pos->name = name;
			}
		}
	}


	static symsort_t analyze(const Elf &elf, bool resolve_relocations, bool explain) {
		symsort_t symbols;
		std::set<Elf::Section, SymbolSort> sections;
		std::set<Elf::Relocation, SymbolSort> relocations;

		// 1. Read symbols and segments
		for (const auto & section: elf.sections) {
			if (section.allocate())
				sections.insert(section);
			switch(section.type()) {
				// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
				case Elf::SHT_REL:
				case Elf::SHT_RELA:
					for (const auto & entry : section.get_relocations())
						relocations.emplace(entry);
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
								if (sym.type() != Elf::STT_NOTYPE) {
									assert(sym.value() >= elf.sections[sym.section_index()].virt_addr());
									assert(sym.value() + sym.size() <= elf.sections[sym.section_index()].virt_addr() + elf.sections[sym.section_index()].size());
								}
								if (sym.value() != 0 && elf.sections[sym.section_index()].allocate())
									insert_symbol(symbols, sym.value(), sym.size(), sym.name());
						}
					break;

				default:
					continue;
			}
		}

		const size_t elf_symbols = symbols.size();
		if (explain) {
			printf("\e[3mElf contains %ld sections with definitions of %ld unqiue symbols and %ld relocations\e[0m\n", sections.size(), elf_symbols, relocations.size());
		}

		// Prepare disassemble
		csh cshandle;
		if (::cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK) // todo: depending on ELF
			return {};
		::cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_insn *insn = cs_malloc(cshandle);

		// 2. Gather (additional) function start addresses by reading call-targets
		//    if call target exists (from symtab)-> ignore
		for (const auto & section : sections) {
			if (section.executable()) {
				const auto index = elf.sections.index(section);
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data());
				uintptr_t address = section.virt_addr();
				insert_symbol(symbols, address, 0, section.name());

				size_t size = section.size();
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					for (size_t g = 0; g < insn->detail->groups_count; g++) {
						if (insn->detail->groups[g] == CS_GRP_CALL) {
							auto & detail_x86 = insn->detail->x86;
							auto & op = detail_x86.operands[detail_x86.op_count - 1];
							if (op.type == X86_OP_IMM)
								insert_symbol(symbols, op.imm);
							else if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
								// Ignore segment, index, scale
								insert_symbol(symbols, insn->address + insn->size + op.mem.disp);
							}
						}
					}
				}
			}
		}

		if (explain) {
			printf("\e[3mFound %ld unqiue symbols in machine code (+%ld compared to definition)\e[0m\n", symbols.size(), (symbols.size() - elf_symbols));
		}

		// 3. Disassemble again...
		size_t last_addr = SIZE_MAX;
		ByteBuffer<128> hashbuf;
		for (auto & sym : symbols) {
			const auto section = sections.lower_bound(sym);
			assert(section != sections.end());

			// 3a. calculate size (if 0), TODO: ignore nops!
			const size_t max_addr = std::min(last_addr, section->virt_addr() + section->size());
			uintptr_t address = sym.address;
			assert(max_addr >= address);
			const size_t max_size = max_addr - address;
			if (max_size > sym.size)
				sym.size = max_size;

			if (explain) {
				printf("\n\e[1m%s\e[0m (%s, %lu bytes)\n", sym.name, section->name(), sym.size);
			}

			// 3b. generate links (from jmp + call) & hash
			const size_t offset = address - section->virt_addr();
			const uint8_t * data = reinterpret_cast<const uint8_t *>(section->data()) + offset;
			XXHash64 id(0);  // TODO seed
			if (section->executable()) {
				size_t size = sym.size - 1;
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					if (insn->id == X86_INS_NOP)
						continue;

					// Buffer for id hash
					hashbuf.clear();
					hashbuf.push(insn->id);  // Instruction ID (Idea: Different call instructions are no issue for comparison - TODO: Is this sufficient)

					auto & detail_x86 = insn->detail->x86;
					// Check Prefix bytes
					size_t prefix_size = 0;
					for (int p = 0; p < 4; p++)
						if (detail_x86.prefix[p] == 0)
							break;
						else
							prefix_size += hashbuf.push(detail_x86.prefix[p]);

					// Has REX prefix? (do not has, since it only affects ops)
					if (detail_x86.rex != 0)
						prefix_size++;

					// Check Opcode bytes
					size_t opcode_size = 0;
					for (int o = 0; o < 4; o++)
						if (detail_x86.opcode[o] == 0)
							break;
						else
							opcode_size += hashbuf.push(detail_x86.opcode[o]);

					// Handle relocations
					const auto relocation = relocations.lower_bound(sym);
					bool relocation_operand[2] = {false, false};
					int rel_start = 0;
					int rel_end = 0;
					const char * rel_name = nullptr;
					if (relocation != relocations.end() && relocation->offset() < insn->address + insn->size) {
						const auto relocator = Relocator(*relocation);
						const auto rel_off = relocation->offset();
						const auto rel_size = relocator.size();
						rel_start = relocation->offset() - insn->address;
						rel_end = rel_start + rel_size;
						//assert(rel_off + rel_size <= insn->address + insn->size);

						if (relocation->symbol_index() == 0) { // TODO: Handling at resolve_relocations
							// No Symbol - calculate target value and add as reference
							sym.ref(relocator.value(0));
							rel_name = "[fixed]";
						} else {
							// Hash relocation type and addend
							hashbuf.push(relocation->type());
							hashbuf.push(relocation->addend());
							// Get relocation symbol
							const auto rel_sym = relocation->symbol();
							rel_name = rel_sym.name();
							if (!resolve_relocations || rel_sym.section_index() == Elf::SHN_UNDEF) {
								// hash symbol name
								id.add(rel_sym.name(), strlen(rel_sym.name()));
							} else {
								// Add as reference -- TODO: Handle weak symbols
								sym.ref(rel_sym.value());
							}
						}

						// Memory should be zero for hash
						for (int i = 0; i < rel_size; i++) {
							assert(*(data - insn->size + (rel_off - insn->address) + i) == 0);
						}

						// Find affected operand (we only support one or two for relocation)
						assert(detail_x86.op_count > 0 && detail_x86.op_count <= 2);
						size_t op = detail_x86.op_count == 2 ? 1 : 0;
						relocation_operand[op] = rel_off + rel_size == insn->address + insn->size;
						relocation_operand[1 - op] = !relocation_operand[op];
					}

					if (explain) {
						printf("0x%016lx", insn->address);
						for (int i = 0; i < 12; i++) {
							if (i < insn->size) {
								if (i >= rel_start && i < rel_end)
									printf("\e[35m");
								else if (i < prefix_size)
									printf("\e[34;3m");
								else if (i < prefix_size + opcode_size)
									printf("\e[34m");
								else
									printf("\e[36m");
								printf(" %02x\e[0m", insn->bytes[i]);
							} else {
								printf("   ");
							}
						}
						printf("\e[34m%s\e[0m \e[36m%s\e[0m", insn->mnemonic, insn->op_str);
						if (rel_name != nullptr)
							printf("\e[35m-> %s\e[0m", rel_name);
						printf("\n");
					}

					// Handle operands
					for (int o = 0; o < detail_x86.op_count; o++) {
						bool has_relocation = o < 2 && relocation_operand[o];
						auto & op = detail_x86.operands[o];
						switch (op.type) {
							case X86_OP_REG:
								assert(!has_relocation);
								hashbuf.push(op.reg);
								break;

							case X86_OP_IMM:
								if (has_relocation) {
									// Skip
								} else if (branch_relative(insn->id)) {
									sym.ref(op.imm);
								} else {
									hashbuf.push(op.imm);
								}
								break;

							case X86_OP_MEM:
								// TODO: segment handling?
								if (op.mem.base == X86_REG_RIP) {
									if (!has_relocation)
										sym.ref(insn->address + insn->size + op.mem.disp);
								} else {
									assert(!has_relocation);
									hashbuf.push(op.mem);
								}
								break;
						}
					}

					// add instruction hash buffer to hash
					id.add(hashbuf.buffer, hashbuf.size);
				}
			} else {
				// Non-executable objects will be fully hashed
				// TODO: Relocations to sym.ref && assert that relocation contents are zero
				if (section->type() != Elf::SHT_NOBITS)
					id.add(data, sym.size);
			}

			sym.id = id.hash();

			last_addr = sym.address;
		}
		cs_free(insn, 1);

		// 4. Calculate full id, set dependencies and add to final set
		for (auto & sym : symbols) {
			if (sym.refs.size() > 0) {
				XXHash64 id_ref(0);  // TODO seed
				for (const auto ref : sym.refs) {
					auto ref_sym = symbols.lower_bound(ref);
					if (ref_sym != symbols.end()) {
						// Hash ID and offset
						const uint64_t r[2] = { ref_sym->id, ref - ref_sym->address};
						id_ref.add(r, 2 * sizeof(uint64_t));
						ref_sym->dep(sym.address);
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
