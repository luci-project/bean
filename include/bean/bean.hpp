#pragma once

#include <dlh/container/vector.hpp>
#include <dlh/container/hash.hpp>
#include <dlh/container/tree.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/stream/buffer.hpp>
#include <dlh/utils/bytebuffer.hpp>
#include <dlh/utils/iterator.hpp>
#include <dlh/utils/string.hpp>
#include <dlh/utils/xxhash.hpp>
#include <dlh/utils/math.hpp>

#include <capstone/capstone.h>
#include <elfo/elf.hpp>
#include <elfo/elf_rel.hpp>

struct Bean {
	/*! \brief Address flag for TLS address */
	static const uintptr_t TLS_ADDRESS_FLAG = 0xf0000000000000;

	enum Verbosity : uint8_t {
		NONE,
		VERBOSE,
		DEBUG,
		TRACE
	};

	struct MemArea {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Flag for writable symbol */
		bool writeable = false;

		/*! \brief Flag for executable symbol */
		bool executable = false;

		MemArea(uintptr_t address, size_t size, bool writeable, bool executable)
		  : address(address), size(size), writeable(writeable), executable(executable) {}

	};

	struct SymbolRelocation {
		uintptr_t offset;
		uintptr_t type;
		const char * name;
		uintptr_t addend;
		uintptr_t target;
		bool undefined;

		SymbolRelocation(uintptr_t offset, uintptr_t type, const char * name = nullptr, uintptr_t addend = 0, bool undefined = false, uintptr_t target = 0)
		  : offset(offset), type(type), name(name), addend(addend), target(target), undefined(undefined) {}

		SymbolRelocation(const Elf::Relocation & relocation, bool resolve_target = false, uintptr_t global_offset_table = 0)
		  : offset(relocation.offset()), type(relocation.type()), name(nullptr), addend(relocation.addend()), target(0) {
			assert(relocation.valid());

			// Get relocation symbol
			if (relocation.symbol_index() != 0) {
				const auto rel_sym = relocation.symbol();
				name = rel_sym.name();
				undefined = (rel_sym.section_index() == Elf::SHN_UNDEF);
			}

			// Perform relocation
			if (resolve_target && !undefined)
				target = Relocator(relocation, global_offset_table).value(0);
		}
	};

	struct Symbol;
	struct SymbolAddressComparison;
	struct SymbolIdentifierComparison;

	typedef TreeSet<Symbol, SymbolAddressComparison> symtree_t;
	typedef HashSet<Symbol, SymbolIdentifierComparison> symhash_t;
	typedef Vector<MemArea> memarea_t;

	struct Symbol {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Symbol name (for debugging) */
		const char * name;

		/*! \brief Section information */
		struct Section {
			/*! \brief Section name (for debugging) */
			const char * name = nullptr;

			/*! \brief Flag for writable symbol */
			bool writeable = false;

			/*! \brief Flag for executable symbol */
			bool executable = false;
		} section;

		/*! \brief Symbol identifier (hash) */
		struct Identifier {
			/*! \brief Identifier based on internal instructions (without refs / rels) */
			uint64_t internal = 0;

			/*! \brief Identifier based on external Refs & and Rels identifier */
			uint64_t external = 0;

			/*! \brief ID set? */
			bool valid() const {
				// TODO: Not robust!
				return internal != 0;
			}

			/*! \brief print ID */
			void dump(BufferStream& bs) const {
				bs << '{' << setfill('0') << hex << setw(16) << internal
				   << ' ' << setfill('0') << hex << setw(16) << external
				   << '}' << reset;
			}

			/*! \brief check if ID matches */
			bool operator==(const Identifier & that) const {
				return this->internal == that.internal && this->external == that.external;
			}
		} id;

		/*! \brief Formatted content */
		const char * debug;

		/*! \brief Symbol ids using this symbol
		 */
		HashSet<uint64_t> deps;

		/*! \brief Reference of used symbols (first = address, second = TLS?) */
		HashSet<uintptr_t> refs;

		/*! \brief Relocations affecting this symbol */
		TreeSet<SymbolRelocation, SymbolAddressComparison> rels;

		Symbol(uintptr_t address, size_t size, const char * name, const char * section_name, bool writeable, bool executable)
		  : address(address), size(size), name(name), section({section_name, writeable, executable}), debug(nullptr) {}

		Symbol(const Symbol &) = default;
		Symbol(Symbol &&) = default;
		Symbol & operator=(const Symbol &) = default;
		Symbol & operator=(Symbol &&) = default;

		void dump_name(BufferStream& bs) const {
			if (address & Bean::TLS_ADDRESS_FLAG)
				bs << "TLS:";
			if (name != nullptr && name[0] != '\0')
				bs << "\e[1m" << name << "\e[21m (";
			else
				bs << "unnamed ";

			bs << dec << size << " bytes @ 0x"
			   << hex << address;

			if (section.name != nullptr)
				bs << ", " << section.name;

			bs << " [r" << (section.writeable ? 'w' : '-') << (section.executable ? 'x' : '-') << ']';
			if (name != nullptr && name[0] != '\0')
				bs << ')';
		}

		static auto dump_address(BufferStream & bs, uintptr_t value, const symtree_t & symbols) {
			if ((value & Bean::TLS_ADDRESS_FLAG) != 0)
				bs << "TLS:";
			bs << "0x" << hex << (value & ~Bean::TLS_ADDRESS_FLAG);
			const auto ref_sym = symbols.floor(value);
			if (ref_sym) {
				bs << " <";
				if (ref_sym->name != nullptr)
					bs << ref_sym->name;
				else {
					if ((ref_sym->address & Bean::TLS_ADDRESS_FLAG) != 0)
						bs << "TLS:";
					bs << "0x" << hex << (ref_sym->address & ~Bean::TLS_ADDRESS_FLAG);;
				}

				if (ref_sym->section.name != nullptr)
					bs << '@' << ref_sym->section.name;

				if (ref_sym->address != value)
					bs << " + " << dec << (value - ref_sym->address);
				bs << '>';
			}
			return ref_sym;
		}

		static void dump_header(BufferStream & bs, Verbosity level = VERBOSE) {
			if (level <= VERBOSE) {
				bs << "{ID               ID refs         }";
				if (level == VERBOSE)
					bs << " [Ref / Rel / Dep] - Address              Size Flg Name (Section)";
				bs << endl;
			}
		}

		void dump(BufferStream & bs, Verbosity level = VERBOSE, const symtree_t * symbols = nullptr, const char * prefix = nullptr) const {
			bs << prefix;
			if (level <= VERBOSE) {
				id.dump(bs);
				if (level == VERBOSE) {
					bs << " [" << setw(3) << right << refs.size() << " / " << setw(3) << right << rels.size() << " / " << setw(3) << right << deps.size() << "] - "
					   << "0x" << setw(16) << setfill('0') << hex << (address & ~Bean::TLS_ADDRESS_FLAG)
					   << dec << setw(7) << setfill(' ') << right << size << ' '
					   << (section.writeable ? 'W' : ' ') << (section.executable ? 'X' : ' ') << ((address & Bean::TLS_ADDRESS_FLAG) != 0 ? 'T' : ' ');
					if (name != nullptr && name[0] != '\0')
						bs << ' ' << name;
					if (section.name != nullptr)
						bs << " (" << section.name << ')';
				}
				bs << endl;
			} else {
				dump_name(bs);

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
								auto ref_sym = dump_address(cout, ref, *symbols);
								if (ref_sym->id.valid()) {
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
							} else {
								bs << "0x" << hex << rel.addend;
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
								auto ref_sym = dump_address(cout, dep, *symbols);
								if (ref_sym->id.valid()) {
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
					bs << "\e[21m" << endl;
				}

				bs << endl;
			}

		}

		bool operator==(const Symbol & that) const {
			return this->id == that.id && this->refs.size() == that.refs.size() && this->deps.size() == that.deps.size();
		}
	};

	struct SymbolAddressComparison {
		static inline int compare(uintptr_t lhs, uintptr_t rhs) {
			return (rhs < lhs) - (lhs < rhs);
		}

		static inline int compare(const Symbol & lhs, const Symbol & rhs) { return compare(lhs.address, rhs.address); }
		static inline int compare(uintptr_t lhs, const Symbol & rhs) { return compare(lhs, rhs.address); }
		static inline int compare(const Symbol & lhs, uintptr_t rhs) { return compare(lhs.address, rhs); }

		static inline int compare(const Elf::Section & lhs, const Elf::Section & rhs) { return compare(lhs.virt_addr() | (lhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0), rhs.virt_addr() | (rhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0)); }
		static inline int compare(const Symbol & lhs, const Elf::Section & rhs) { return compare(lhs.address, rhs.virt_addr() | (rhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0)); }
		static inline int compare(const Elf::Section & lhs, const Symbol & rhs) { return compare(lhs.virt_addr() | (lhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0), rhs.address); }
		static inline int compare(uintptr_t lhs, const Elf::Section & rhs) { return compare(lhs, rhs.virt_addr() | (rhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0)); }
		static inline int compare(const Elf::Section & lhs, uintptr_t rhs) { return compare(lhs.virt_addr() | (lhs.tls() ? Bean::TLS_ADDRESS_FLAG : 0), rhs); }

		static inline int compare(const Elf::Relocation & lhs, const Elf::Relocation & rhs) { return compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const Elf::Relocation & rhs) { return compare(lhs.address & ~Bean::TLS_ADDRESS_FLAG, rhs.offset()); }
		static inline int compare(const Elf::Relocation & lhs, const Symbol & rhs) { return compare(lhs.offset(), rhs.address & ~Bean::TLS_ADDRESS_FLAG); }
		static inline int compare(uintptr_t lhs, const Elf::Relocation & rhs) { return compare(lhs, rhs.offset()); }
		static inline int compare(const Elf::Relocation & lhs, uintptr_t rhs) { return compare(lhs.offset(), rhs); }

		static inline int compare(const SymbolRelocation & lhs, const SymbolRelocation & rhs) { return compare(lhs.offset, rhs.offset); }
		static inline int compare(uintptr_t lhs, const SymbolRelocation & rhs) { return compare(lhs, rhs.offset); }
		static inline int compare(const SymbolRelocation & lhs, uintptr_t rhs) { return compare(lhs.offset, rhs); }
	};

	struct SymbolIdentifierComparison: public Comparison {
		using Comparison::equal;
		using Comparison::hash;

		static inline uint32_t hash(const Symbol& sym) { return Comparison::hash(sym.id.internal ^ sym.id.external); }

		static inline bool equal(const Symbol & lhs, const Symbol & rhs) { return lhs == rhs; }
	};

	const symtree_t symbols;

	explicit Bean(const Elf & elf, bool resolve_internal_relocations = true, bool debug = false) : symbols(analyze(elf, resolve_internal_relocations, debug)) {}

	void dump(BufferStream & bs, Verbosity level = NONE) const {
		auto foo = *symbols.highest();
		dump(bs, symbols, level);
	}

	static void dump(BufferStream & bs, const symtree_t & symbols, Verbosity level = NONE) {
		Symbol::dump_header(bs, level);
		for (const auto & sym : symbols)
			sym.dump(bs, level, &symbols);
	}

	static void dump(BufferStream & bs, const symhash_t & symbols, Verbosity level = NONE) {
		if (level > NONE) {
			// Sort output by address
			dump(bs, symtree_t(symbols), level);
		} else {
			// unsorted
			for (const auto & sym: symbols)
				sym.dump(bs, level);
		}
	}

	/*! \brief Merge memory areas */
	const memarea_t merge(const symtree_t & symbols, size_t threshold = 0) const {
		memarea_t area;
		for (const auto & sym : symbols) {
			if (!area.empty()) {
				auto & last = area.back();
				if (last.writeable == sym.section.writeable && last.executable == sym.section.executable &&  last.address + last.size + threshold >= sym.address) {
					last.size = sym.address + sym.size - last.address;
					continue;
				}
			}
			area.emplace_back(sym.address, sym.size, sym.section.writeable, sym.section.executable);
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

	static void insert_symbol(symtree_t & symbols, uintptr_t address, size_t size = 0, const char * name = nullptr, const char * section_name = nullptr, bool writeable = false, bool executable = false) {
		assert(!(executable && writeable));
		assert(!(executable && (address & Bean::TLS_ADDRESS_FLAG)));
		auto pos = symbols.find(address);
		if (!pos) {
			symbols.emplace(address, size, name, section_name, writeable, executable);
		} else {
			if (pos->section.name == nullptr && section_name != nullptr)
				pos->section.name = section_name;
			assert(pos->section.writeable == writeable);
			assert(pos->section.executable == executable);

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

	static symtree_t analyze(const Elf &elf, bool resolve_internal_relocations, bool debug, size_t buffer_size = 1048576) {
		symtree_t symbols;
		TreeSet<Elf::Section, SymbolAddressComparison> sections;
		TreeSet<Elf::Relocation, SymbolAddressComparison> relocations;

		// TODO: TLS refs (fs:[...])

		size_t page_size = 0x1000;
		uintptr_t global_offset_table = 0;
		uintptr_t tls_start = 0;
		uintptr_t tls_end = 0;

		// 1. Read symbols and segments

		// Read Program header table
		for (const auto & segment: elf.segments) {
			switch (segment.type()) {
				case Elf::PT_TLS:
					tls_start = segment.virt_addr();
					tls_end = Math::align_up(segment.virt_addr() + segment.virt_size(), segment.alignment());
					break;

				case Elf::PT_LOAD:
					if (page_size < segment.alignment())
						page_size = segment.alignment();
					break;

				// TODO: Other entries can be used to insert symbol borders
			}
		}


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
					for (const auto & sym: section.get_symbols()) {
						switch (sym.section_index()) {
							case Elf::SHN_UNDEF:
							case Elf::SHN_ABS:
							case Elf::SHN_COMMON:
							case Elf::SHN_XINDEX:
								break;

							default:
							{
								auto sym_sec = elf.sections[sym.section_index()];
								if (sym.type() == Elf::STT_TLS) {
									assert(sym_sec.tls());
									insert_symbol(symbols, (tls_start + sym.value()) | TLS_ADDRESS_FLAG, sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								} else {
									assert((sym.value() & TLS_ADDRESS_FLAG) == 0);
									if (sym.type() != Elf::STT_NOTYPE) {
										assert(sym.value() >= sym_sec.virt_addr());
										assert(sym.value() + sym.size() <= sym_sec.virt_addr() + sym_sec.size());
									}
									if (sym.value() != 0 && elf.sections[sym.section_index()].allocate())
										insert_symbol(symbols, sym.value() | (sym_sec.tls() ? TLS_ADDRESS_FLAG : 0), sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								}
							}
						}
					}
					break;

				case Elf::SHT_DYNAMIC:
					for (const auto & dyn: section.get_dynamic())
						switch(dyn.tag()) {
							case Elf::DT_PLTGOT:
								global_offset_table = dyn.value();
								break;

							// TODO: Other entries can be used to insert symbol borders
						}
					break;

				default:
					continue;
			}
		}

		// use Relocation targets to identify symbols
		for (const auto & rel : relocations)
			switch (rel.type()) {
				case Elf::R_X86_64_RELATIVE:
				case Elf::R_X86_64_RELATIVE64:
				{
					auto sec = sections.floor(static_cast<uintptr_t>(rel.addend()));
					assert(sec);
					assert(!sec->tls());
					insert_symbol(symbols, rel.addend(), 0, nullptr, sec->name(), sec->writeable(), sec->executable());
				}
				default:
					break;
			}

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
			// Add section start
			uintptr_t address = section.virt_addr();
			size_t size = section.size();
			insert_symbol(symbols, address | (section.tls() ? TLS_ADDRESS_FLAG : 0), 0, nullptr, section.name(), section.writeable(), section.executable());

			// Find calls in exec
			if (section.executable()) {
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data());

				// For better readability, name the PLT functions
				bool plt_name = debug && strncmp(section.name(), ".plt.", 5) == 0;

				// start of current function
				uintptr_t start = address;

				// was the last instruction a return (or other)?
				bool ret = false;
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					i++;

					// The sequence "ret; (nop;) endbr" indicates the start of a new symbol
					switch (insn->id) {
						case X86_INS_NOP:
							continue;

						case X86_INS_JMP:
						case X86_INS_HLT:
						case X86_INS_SYSEXIT:
						case X86_INS_SYSRET:
							ret = true;
							break;

						case X86_INS_ENDBR32:
						case X86_INS_ENDBR64:
							start = insn->address;
							if (ret) {
								insert_symbol(symbols, start | (section.tls() ? TLS_ADDRESS_FLAG : 0), 0, nullptr, section.name(), section.writeable(), section.executable());
								ret = false;
							}
							break;

						default:
							ret = false;
							break;
					}

					for (size_t g = 0; g < insn->detail->groups_count; g++) {
						switch (insn->detail->groups[g]) {
							case CS_GRP_JUMP:
								if (plt_name) {
									assert(insn->detail->x86.op_count == 1);
									auto & op = insn->detail->x86.operands[0];
									assert(op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP);

									const auto relocation = relocations.find(insn->address + insn->size + op.mem.disp);
									assert(relocation && relocation->symbol_index() != 0);
									auto name = relocation->symbol().name();

									auto pos = symbols.find(start);
									if (pos)
										pos->name = name;
									else {
										auto sec = sections.floor(start);
										assert(sec);
										symbols.emplace(start, (address - start) | (sec->tls() ? TLS_ADDRESS_FLAG : 0), name, sec->name(), sec->writeable(), sec->executable());
									}
								}
								break;

							case CS_GRP_CALL:
							{
								auto & detail_x86 = insn->detail->x86;
								auto & op = detail_x86.operands[detail_x86.op_count - 1];
								uintptr_t target = 0;
								if (op.type == X86_OP_IMM)
									target = op.imm;
								else if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP)
									target = insn->address + insn->size + op.mem.disp;
								else
									continue;

								// Only in executable sections
								const auto section = sections.floor(target);
								if (section && section->executable())
									insert_symbol(symbols, target | (section->tls() ? TLS_ADDRESS_FLAG : 0), 0, nullptr, section->name(), section->writeable(), true);

								break;
							}
							case CS_GRP_RET:
							case CS_GRP_IRET:
								ret = true;
								break;
						}
					}
				}
			}
		}

		// 3. Disassemble again...
		{
			// Prepare temporary stream buffer (used in debug mode only)
			char * debug_buffer = nullptr;
			if (debug) {
				debug_buffer = reinterpret_cast<char*>(malloc(buffer_size));
				assert(debug_buffer != nullptr);
			}
			BufferStream debug_stream(debug_buffer, buffer_size);

			// Iterate over all symbols
			size_t last_addr = SIZE_MAX;
			ByteBuffer<128> hashbuf;

			for (auto & sym : reverse(symbols)) {
				const auto section = sections.floor(sym);
				assert(section);

				// Set symbol section flags
				if (sym.section.name == nullptr) {
					sym.section.name = section->name();
					sym.section.executable = section->executable();
					sym.section.writeable = section->writeable();
				}

				if (debug && sym.address == global_offset_table)
					debug_stream << "  \e[3m[the global offset table]\e[0m" << endl;

				// 3a. calculate size (if 0), TODO: ignore nops!
				const size_t max_addr = Math::min(last_addr, (section->virt_addr() + section->size()) | (section->tls() ? TLS_ADDRESS_FLAG : 0));
				uintptr_t address = sym.address & ~TLS_ADDRESS_FLAG;
				assert(max_addr >= sym.address);
				const size_t max_size = max_addr - sym.address;
				if (max_size > sym.size)
					sym.size = max_size;

				// 3b. generate links (from jmp + call) & hash
				const size_t offset = address - section->virt_addr();
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section->data()) + offset;
				XXHash64 id_internal(0);  // TODO seed
				if (sym.section.executable) {
					assert(!section->tls());
					size_t size = sym.size;
					bool leave = true;
					size_t last_instruction = address;
					size_t max_branch = address;
					while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
						switch (insn->id) {
							case X86_INS_NOP:
								continue;
							case X86_INS_JMP:
							case X86_INS_LJMP:
							case X86_INS_RET:
							case X86_INS_RETF:
							case X86_INS_RETFQ:
							case X86_INS_HLT:
							// Rare
							case X86_INS_IRET:
							case X86_INS_IRETD:
							case X86_INS_IRETQ:
							case X86_INS_SYSEXIT:
							case X86_INS_SYSRET:
								leave = true;
								break;
							default:
								leave = false;
						}
						last_instruction = address;  // Ignores nop

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

						// Has REX prefix? (do not hash, since it only affects ops)
						if (detail_x86.rex != 0)
							prefix_size++;

						// Check Opcode bytes
						size_t opcode_size = 0;
						for (int o = 0; o < 4; o++)
							if (detail_x86.opcode[o] == 0)
								break;
							else
								opcode_size += hashbuf.push(detail_x86.opcode[o]);

						// Helper for debug
						int debug_ignore = 255;
						struct {
							bool hashed = true;
							bool relocation = false;
							uintptr_t value = 0;
						} op_debug[detail_x86.op_count];

						// Handle operands
						for (int o = 0; o < detail_x86.op_count; o++) {
							auto & op = detail_x86.operands[o];

							switch (op.type) {
								case X86_OP_REG:
									hashbuf.push(op.reg);
									break;

								case X86_OP_IMM:
								{
									const auto target = static_cast<uintptr_t>(op.imm);
									if (branch_relative(insn->id)) {
										op_debug[o].value = target;

										// Inside symbol?
										if (target >= sym.address && target < sym.address + sym.size) {
											max_branch = target;
											// same symbol, hence just hash
											hashbuf.push(target - sym.address);
										} else {
											// other symbol, add reference
											sym.refs.insert(target);
											op_debug[o].hashed = false;
										}
									} else {
										hashbuf.push(target);
									}
									break;
								}

								case X86_OP_MEM:
									// TODO: segment handling?
									if (op.mem.segment == X86_REG_FS) {
										const auto target = (tls_end + op.mem.disp) | TLS_ADDRESS_FLAG;
										sym.refs.insert(target);

										op_debug[o].hashed = false;
										op_debug[o].value = static_cast<uintptr_t>(target);
									}
									if (op.mem.base == X86_REG_RIP) {
										const auto target = insn->address + insn->size + op.mem.disp;
										sym.refs.insert(target);

										op_debug[o].hashed = false;
										op_debug[o].value = static_cast<uintptr_t>(target);
									} else {
										hashbuf.push(op.mem);
									}
									break;

								default:
									break;
							}

							if (debug_ignore > o && !op_debug[o].hashed) {
								debug_ignore = o;
								if (o == 0 && detail_x86.modrm != 0)
									debug_ignore++;
							}
						}

						if (debug) {
							debug_stream << setfill(' ') << setw(16) << prefix << right << hex << insn->address << ' ' << setfill('0') << noprefix;
							int op = 0;
							size_t op_size = 0;
							for (size_t i = 0; i < 12; i++) {
								if (i < insn->size) {
									debug_stream << ' ';
									if (i < prefix_size)
										debug_stream << "\e[34;3m";
									else if (i < prefix_size + opcode_size)
										debug_stream << "\e[34m";
									else if (i >= prefix_size + opcode_size + debug_ignore)
										// This is not necessarly accurate - depending on the encoding
										// however it is only for hash visualization, the real hash uses the disassembled inormation instead of the machine code bytes
										debug_stream << "\e[35m";
									else
										debug_stream << "\e[36m";
									debug_stream << setw(2) << static_cast<int>(insn->bytes[i]) << "\e[0m";
								} else {
									debug_stream << "   ";
								}
							}
							debug_stream << "\e[34m" << insn->mnemonic << "\e[0m ";
							auto ops = String::split(insn->op_str, ',');
							for (int o = 0; o < detail_x86.op_count; o++) {
								if (o > 0)
									debug_stream << "\e[36m,";
								if (!op_debug[o].hashed)
									debug_stream << "\e[35m";
								else if (o == 0)
									debug_stream << "\e[36m";
								debug_stream << ops[o] << "\e[0m";
							}

							// Additional information for reference operands
							bool hashtag = false;
							for (int o = 0; o < detail_x86.op_count; o++) {
								auto & op = op_debug[o];
								if (op.value != 0) {
									debug_stream << (hashtag ? "  " : "  # ");
									hashtag = true;
									if (op.hashed)
										debug_stream << "\e[3m";
									Symbol::dump_address(debug_stream, op.value, symbols);
									if (op.hashed)
										debug_stream << "\e[0m";

									// Check if target is a relocated value (GOT)
									const auto relocation = relocations.find(op.value);
									if (relocation != relocations.end()) {
										assert(relocation->valid());

										debug_stream << " \e[3m[";
										if (relocation->symbol_index() == 0) {
											// No Symbol - calculate target value and add as reference
											Symbol::dump_address(debug_stream, Relocator(*relocation).value(0), symbols);
										} else {
											// Get relocation symbol
											const auto rel_sym = relocation->symbol();
											if (rel_sym.section_index() == Elf::SHN_UNDEF)
												debug_stream << rel_sym.name();
											else
												debug_stream << "0x" << hex << rel_sym.value();
											if (relocation->addend() != 0)
												debug_stream << " + " << dec << relocation->addend();
										}
										debug_stream << "]\e[0m";
									}
								}
							}
							debug_stream << endl;
						}

						// add instruction hash buffer to hash
						id_internal.add(hashbuf.buffer(), hashbuf.size());
					}

					// If it doesn't end with a leave instruction (ret), or a branch jumps beyond it, we have to link it to the next function (fallthrough)
					if (!leave || max_branch > last_instruction) {
						auto next = symbols.ceil(sym.address + sym.size);
						assert(next);
						sym.refs.insert(next->address);
					}
				} else {
					// 3c. Link relocations to (data) symbols (not for .bss in TLS)
					if (section->type() != Elf::SHT_NOBITS || !section->tls())
						for (auto relocation = relocations.ceil(sym); relocation != relocations.end() && relocation->offset() < address + sym.size; ++relocation) {
							auto r = sym.rels.emplace(*relocation, resolve_internal_relocations, global_offset_table);
							// Add local (internal) relocation as reference
							if (r.second && resolve_internal_relocations && !r.first->undefined)
								sym.refs.insert(r.first->target);
						}

					// Symbols of writeable sections (.data) are depending on the alignment of their (virtual) address
					if (sym.section.writeable)
						id_internal.add<uint32_t>(address % page_size);

					// Non-executable objects will be fully hashed
					if (section->type() != Elf::SHT_NOBITS)
						id_internal.add(data, sym.size);
					else
						id_internal.addZeros(sym.size);  // bss

					if (debug && sym.size > 0) {
						const size_t bytes_per_line = 16;
						// relocations
						auto rel = sym.rels.lowest();
						bool had_rel = false;
						size_t rel_end = 0;

						// ASCII representation
						int is_ascii = 0;
						char ascii[bytes_per_line * 2] = {};
						size_t ascii_size = 0;
						for (size_t a = Math::align_down(address, bytes_per_line); a < Math::align_up(address + sym.size, bytes_per_line); a++) {
							if (a % bytes_per_line == 0)
								debug_stream << setfill(' ') << setw(16) << prefix << right << hex << a << ' '
								             << (a < rel_end ? "\e[33;4m" : "\e[33m") << setfill('0') << noprefix;
							if (a < address || a >= address + sym.size) {
								if (rel && a == rel_end)
									debug_stream << "\e[0m";
								debug_stream << "   ";
								ascii[ascii_size++] = ' ';
							} else {
								if (rel && a == rel_end) {
									debug_stream << "\e[0;33m ";
									rel_end = 0;
									++rel;
								} else {
									debug_stream << ' ';
								}
								if (rel && a == rel->offset) {
									debug_stream << "\e[33;4m";
									had_rel = true;
									rel_end = rel->offset + Relocator<Elf::Relocation>::size(rel->type, elf.header.machine());
								}
								int val = static_cast<int>(section->type() != Elf::SHT_NOBITS ? data[a - address] : 0);
								debug_stream << setw(2) << val;
								if (val >= 32 && val < 127) {
									ascii[ascii_size++] = static_cast<char>(val);
									is_ascii++;
									if (val == 92)
										ascii[ascii_size++] = '\\';
								} else {
									is_ascii--;
									ascii[ascii_size++] = ' ';
								}
							}
							if ((a + 1) % bytes_per_line == 0) {
								debug_stream << "\e[0m";
								if (had_rel) {
									debug_stream << "  #";
									for (auto r = sym.rels.ceil(a - bytes_per_line); r && r->offset <= a; ++r ) {
										debug_stream << " \e[4m";
										if (r->name != nullptr) {
											debug_stream << r->name;
											if (r->addend != 0)
												debug_stream << " + " << dec << r->addend;
										} else {
											Symbol::dump_address(debug_stream, resolve_internal_relocations ? r->target : r->addend, symbols);
										}
										debug_stream << "\e[0m";
									}

									had_rel = false;
								} else if (is_ascii > 0) {
									debug_stream << "  \e[3m# ";
									debug_stream.write(ascii, ascii_size);
									debug_stream << "\e[0m";
								}
								is_ascii = 0;
								ascii_size = 0;
								debug_stream << endl;
							}
						}
					}
				}

				if (debug) {
					// Duplicate buffer for symbol
					size_t len = 0;
					const char * buf = debug_stream.str(len);
					if (buf != nullptr && len > 0) {
						char * tmp = reinterpret_cast<char*>(malloc(len + 1));
						assert(tmp != nullptr);
						memcpy(tmp, buf, len);
						tmp[len] = '\0';
						sym.debug = tmp;
					}
					// Clear for next symbol
					debug_stream.clear();
				}

				// Calculate has
				sym.id.internal = id_internal.hash();

				last_addr = sym.address;
			}

			// Clear temporary stream buffer
			if (debug)
				free(debug_buffer);
		}

		// Clear instruction buffer
		cs_free(insn, 1);


		// 4. Calculate full id, set dependencies and add to final set
		for (auto & sym : symbols) {
			if (sym.rels.size() > 0 || sym.refs.size() > 0 ) {
				XXHash64 id_external(0);  // TODO seed
				// Relocations
				for (const auto rel : sym.rels) {
					id_external.add<uintptr_t>(rel.offset);
					id_external.add<uintptr_t>(rel.type);
					id_external.add(rel.name, strlen(rel.name));
					id_external.add<uintptr_t>(rel.addend);
				}
				// References
				for (const auto ref : sym.refs) {
					auto ref_sym = symbols.floor(ref);
					if (ref_sym) {
						// Hash ID and offset
						id_external.add<uint64_t>(ref_sym->id.internal);
						id_external.add<uint64_t>(ref - ref_sym->address);
						ref_sym->deps.insert(sym.address);
					} else {
						// TODO
					}
				}
				sym.id.external = id_external.hash();
			}
		}

		return symbols;
	}
};

static inline BufferStream& operator<<(BufferStream& bs, const Bean::Symbol & sym) {
	sym.dump_name(bs);
	return bs;
}

static inline BufferStream& operator<<(BufferStream& bs, const Bean::Symbol::Identifier & id) {
	if (id.valid())
		id.dump(bs);
	else
		bs << "{\e[3munknown ID\e23m}";
	return bs;
}
