#pragma once

#include <dlh/container/hash.hpp>
#include <dlh/container/tree.hpp>
#include <dlh/container/vector.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/utils/bytebuffer.hpp>
#include <dlh/utils/iterator.hpp>
#include <dlh/utils/xxhash.hpp>
#include <dlh/utils/math.hpp>

#include <capstone/capstone.h>
#include <elfo/elf.hpp>
#include <elfo/elf_rel.hpp>

struct Bean {
 	struct Symbol {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Symbol name (for debugging) */
		const char * name;

		/*! \brief Identifier based on instructions (without refs) */
		uint64_t id;

		/*! \brief Refs identifier */
		uint64_t id_ref;

		/*! \brief Symbol ids using this symbol
		 */
		HashSet<uintptr_t> deps;

		/*! \brief Reference of used symbols */
		HashSet<uintptr_t> refs;

		Symbol(uintptr_t address, size_t size, const char * name = nullptr) : address(address), size(size), name(name), id(0), id_ref(0)  {}
		Symbol(const Symbol &) = default;
		Symbol(Symbol &&) = default;
		Symbol & operator=(const Symbol &) = default;
		Symbol & operator=(Symbol &&) = default;

		static void dump_header() {
			cout << "ID               ID refs          [Ref / Dep] - Address              Size Name" << endl;
		}

		void dump(bool verbose = false) const {
			cout << setfill('0') << hex
				 << setw(16) << id << ' '
				 << setw(16) << id_ref
				 << setfill(' ') << dec;
			if (verbose)
				cout << " [" << setw(3) << right << refs.size() << " / " << setw(3) << right << deps.size() << "] - "
				     << "0x" << setw(16) << setfill('0') << hex << address
				     << dec << setw(7) << setfill(' ') << right << size << ' ' << name;
			cout << endl;
		}

		bool operator==(const Symbol & that) const {
			return this->id == that.id && this->id_ref == that.id_ref && this->refs.size() == that.refs.size() && this->deps.size() == that.deps.size();
		}
	};

	struct SymbolComparison: public Comparison {
		using Comparison::compare;
		using Comparison::equal;
		using Comparison::hash;

		static inline int compare(const Symbol & lhs, const Symbol & rhs) { return Comparison::compare(lhs.address, rhs.address); }
		static inline int compare(uintptr_t lhs, const Symbol & rhs) { return Comparison::compare(lhs, rhs.address); }
		static inline int compare(const Symbol & lhs, uintptr_t rhs) { return Comparison::compare(lhs.address, rhs); }

		static inline int compare(const Elf::Section & lhs, const Elf::Section & rhs) { return Comparison::compare(lhs.virt_addr(), rhs.virt_addr()); }
		static inline int compare(const Symbol & lhs, const Elf::Section & rhs) { return Comparison::compare(lhs.address, rhs.virt_addr()); }
		static inline int compare(const Elf::Section & lhs, const Symbol & rhs) { return Comparison::compare(lhs.virt_addr(), rhs.address); }

		static inline int compare(const Elf::Relocation & lhs, const Elf::Relocation & rhs) { return Comparison::compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const Elf::Relocation & rhs) { return Comparison::compare(lhs.address, rhs.offset()); }
		static inline int compare(const Elf::Relocation & lhs, const Symbol & rhs) { return Comparison::compare(lhs.offset(), rhs.address); }
		static inline int compare(uintptr_t lhs, const Elf::Relocation & rhs) { return Comparison::compare(lhs, rhs.offset()); }
		static inline int compare(const Elf::Relocation & lhs, uintptr_t rhs) { return Comparison::compare(lhs.offset(), rhs); }

		static inline uint32_t hash(const Symbol& sym) { return Comparison::hash(sym.id ^ sym.id_ref); }

		template<typename T, typename U>
		static inline bool equal(const T& a, const U& b) { return compare(a, b) == 0; }
	};

	typedef HashSet<Symbol, SymbolComparison> symhash_t;
	typedef TreeSet<Symbol, SymbolComparison> symtree_t;
	typedef Vector<Pair<uintptr_t, size_t>> memarea_t;

	const Elf & elf;
	const symtree_t symbols;

	explicit Bean(const Elf & elf, bool resolve_relocations = true, bool explain = false) : elf(elf), symbols(analyze(elf, resolve_relocations, explain)) {}

	void dump(bool verbose = false) const {
		auto foo = *symbols.highest();
		dump(symbols, verbose);
	}

	static void dump(const symtree_t & symbols, bool verbose = false) {
		if (verbose)
			Symbol::dump_header();
		for (const auto & sym : symbols)
			sym.dump(verbose);
	}

	static void dump(const symhash_t & symbols, bool verbose = false) {
		if (verbose) {
			// Sort output by address
			dump(symtree_t(symbols), verbose);
		} else {
			// unsorted
			for (const auto & sym: symbols)
				sym.dump(verbose);
		}
	}

	/*! \brief Merge memory areas */
	const memarea_t merge(const symtree_t & symbols, size_t threshold = 0) const {
		memarea_t area;
		for (const auto & sym : symbols) {
			if (!area.empty()) {
				const auto & address = area.back().first;
				auto & size = area.back().second;
				if (address + size + threshold >= sym.address) {
					size = sym.address + sym.size - address;
					continue;
				}
			}
			area.emplace_back(sym.address, sym.size);
		}
		return area;
	}

	/*! \brief Merge memory areas
	 * \note ids and names will be removed
	 */
	const memarea_t merge(const symhash_t & symbols, size_t threshold = 0) const {
		return merge(symtree_t(symbols), threshold);
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
			if (!other_symbols.contains(sym) && result.insert(sym).second && include_dependencies)
				for (const auto d: sym.deps)
					dependencies(d, result);
		return result;
	}

	const symhash_t diff(const Bean & other, bool include_dependencies = false) const {
		return diff(symhash_t(other.symbols), include_dependencies);
	}

	const Symbol * get(uintptr_t address)  const  {
		auto sym = symbols.floor(address);
		return sym && address < sym->address + sym->size ? &(*sym) : nullptr;
	}

	auto find(uintptr_t address = 0) const {
		return symbols.floor(address);
	}

	auto begin() const {
		return symbols.begin();
	}

	auto end() const {
		return symbols.end();
	}

 private:
	void dependencies(uintptr_t address, symhash_t & result) const {
		auto sym = symbols.ceil(address);
		if (sym && result.emplace(*sym).second)
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

	static void insert_symbol(symtree_t & symbols, uintptr_t address, size_t size = 0, const char * name = nullptr) {
		auto pos = symbols.find(address);
		if (!pos) {
			symbols.emplace(address, size, name);
		} else {
			const auto max_address = Math::max(pos->address + pos->size, address + size);
			bool new_name = name != nullptr &&  (pos->name == nullptr || pos->name[0] == '\0');
			if (address < pos->address) {
				auto && sym = symbols.extract(pos);
				sym.value().address = address;
				sym.value().size = max_address - address;
				if (new_name)
					sym.value().name = name;
				symbols.insert(move(sym));
			} else {
				pos->size = max_address - pos->address;
				if (new_name)
					pos->name = name;
			}
		}
	}


	static symtree_t analyze(const Elf &elf, bool resolve_relocations, bool explain) {
		symtree_t symbols;
		TreeSet<Elf::Section, SymbolComparison> sections;
		TreeSet<Elf::Relocation, SymbolComparison> relocations;

		// 1. Read symbols and segments
		for (const auto & section: elf.sections) {
			if (section.allocate())
				sections.insert(section);
			switch(section.type()) {
				// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
				case Elf::SHT_REL:
				case Elf::SHT_RELA:
					for (const auto & entry : section.get_relocations()) {
						relocations.emplace(entry);
					}
					break;

				case Elf::SHT_SYMTAB:
				case Elf::SHT_DYNSYM:
					for (auto & sym: section.get_symbols()) {
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
					}
					break;

				default:
					continue;
			}
		}

		const size_t elf_symbols = symbols.size();
		if (explain)
			cout << "\e[3mElf contains " << sections.size() << " sections with definitions of " << elf_symbols << " unqiue symbols and " << relocations.size() << " relocations\e[0m" << endl;

		// Prepare disassemble
		csh cshandle;
		if (::cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)  // todo: depending on ELF
			assert(false);

		::cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_insn *insn = ::cs_malloc(cshandle);

		// 2. Gather (additional) function start addresses by reading call-targets
		//    if call target exists (from symtab)-> ignore
		int i = 0;
		for (const auto & section : sections) {
			if (section.executable()) {
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data());
				uintptr_t address = section.virt_addr();
				insert_symbol(symbols, address, 0, section.name());
				size_t size = section.size();
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					i++;
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

		if (explain)
			cout << "\e[3mFound " << symbols.size() << " unqiue symbols in machine code (+" << (symbols.size() - elf_symbols) << " compared to definition)\e[0m" << endl;


		// 3. Disassemble again...
		size_t last_addr = SIZE_MAX;
		ByteBuffer<128> hashbuf;
		for (auto & sym : reverse(symbols)) {
			const auto section = sections.floor(sym);
			assert(section);

			// 3a. calculate size (if 0), TODO: ignore nops!
			const size_t max_addr = Math::min(last_addr, section->virt_addr() + section->size());
			uintptr_t address = sym.address;
			assert(max_addr >= address);
			const size_t max_size = max_addr - address;
			if (max_size > sym.size)
				sym.size = max_size;

			if (explain)
				cout << endl << "\e[1m" << sym.name << "\e[0m (" << section->name() << ", " << sym.size << " bytes)" << endl;

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
					const auto relocation = relocations.floor(sym);
					bool relocation_operand[2] = {false, false};
					size_t rel_start = 0;
					size_t rel_end = 0;
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
							sym.refs.insert(relocator.value(0));
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
								sym.refs.insert(rel_sym.value());
							}
						}

						// Memory should be zero for hash
						for (size_t i = 0; i < rel_size; i++) {
							assert(*(data - insn->size + (rel_off - insn->address) + i) == 0);
						}

						// Find affected operand (we only support one or two for relocation)
						assert(detail_x86.op_count > 0 && detail_x86.op_count <= 2);
						size_t op = detail_x86.op_count == 2 ? 1 : 0;
						relocation_operand[op] = rel_off + rel_size == insn->address + insn->size;
						relocation_operand[1 - op] = !relocation_operand[op];
					}

					if (explain) {
						cout << setfill('0') << setw(16) << hex << insn->address;
						for (size_t i = 0; i < 12; i++) {
							if (i < insn->size) {
								if (i >= rel_start && i < rel_end)
									cout << "\e[35m";
								else if (i < prefix_size)
									cout << "\e[34;3m";
								else if (i < prefix_size + opcode_size)
									cout << "\e[34m";
								else
									cout << "\e[36m";
								cout << ' ' << setw(2) << insn->bytes[i] << "\e[0m";
							} else {
								cout << "   ";
							}
						}
						cout << "\e[34m" << insn->mnemonic << "\e[0m \e[36m" << insn->op_str << "\e[0m";
						if (rel_name != nullptr)
							cout << "\e[35m-> " << rel_name << "\e[0m";
						cout << endl;
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
									sym.refs.insert(op.imm);
								} else {
									hashbuf.push(op.imm);
								}
								break;

							case X86_OP_MEM:
								// TODO: segment handling?
								if (op.mem.base == X86_REG_RIP) {
									if (!has_relocation)
										sym.refs.insert(insn->address + insn->size + op.mem.disp);
								} else {
									assert(!has_relocation);
									hashbuf.push(op.mem);
								}
								break;

							default:
								break;
						}
					}

					// add instruction hash buffer to hash
					id.add(hashbuf.buffer(), hashbuf.size());
				}
			} else {
				// Non-executable objects will be fully hashed
				// TODO: Relocations to sym.ref && assert that relocation contents are zero
				if (section->type() != Elf::SHT_NOBITS)
					id.add(data, sym.size);
				else
					id.addZeros(sym.size);  // bss
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
					auto ref_sym = symbols.floor(ref);
					if (ref_sym) {
						// Hash ID and offset
						const uint64_t r[2] = { ref_sym->id, ref - ref_sym->address};
						id_ref.add(r, 2 * sizeof(uint64_t));
						ref_sym->deps.insert(sym.address);
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
