#pragma once

#include <dlh/bytebuffer.hpp>
#include <dlh/iterator.hpp>
#include <dlh/string.hpp>
#include <dlh/xxhash.hpp>
#include <dlh/math.hpp>

#include <capstone/capstone.h>
#include <elfo/elf.hpp>
#include <elfo/elf_rel.hpp>

template<ELFCLASS C>
class AnalyzeX86 : public Analyze<C> {
	/*! \brief Capstone handle to dissassemble machine code*/
	csh cshandle;

	/*! \brief Preallocated capstone instruction buffer */
	cs_insn *insn = nullptr;

	/*! \brief use Relocation targets to identify additional symbols */
	void read() {
		for (const auto & rel : this->relocations)
			switch (rel.type()) {
				case ELF<C>::R_X86_64_RELATIVE:
				case ELF<C>::R_X86_64_RELATIVE64:
				case ELF<C>::R_X86_64_IRELATIVE:
				{
					auto sec = this->sections.floor(static_cast<uintptr_t>(rel.addend()));
					assert(sec);
					assert(rel.type() != ELF<C>::R_X86_64_IRELATIVE || sec->executable());
					assert(!sec->tls());
					this->insert_symbol(rel.addend(), 0, nullptr, sec->name(), sec->writeable(), sec->executable());
					// fall through
					__attribute__((__fallthrough__));
				}
#ifdef BEAN_VERBOSE
				default:
					if (this->debug) {
						// Verify only writeable data sections are relocated
						auto sec = this->sections.floor(static_cast<uintptr_t>(rel.offset()));
						assert(sec);
						assert(sec->allocate());
						if (!sec->writeable())
							cerr << "Warning: Relocation of type " << (int)rel.type() << " at " << (void*)rel.offset() << " in non-writeable section " << sec->name() << endl;

						assert(!sec->executable());
					}
#endif
			}
	}

	/*! \brief Find additional function start addresses
	 * In dissassembled executable sections,
	 *  - the target address of a `call` instruction and
	 *  - `ret; [nop;] endbr64` statements (when compiled with
	 *     support for Intel CET / IBT [indirect-branch tracking])
	 * hint a function start.
	 */
	void find_additional_functions() {
		int i = 0;
		for (const auto & section : this->sections) {
			// Add section start
			uintptr_t address = section.virt_addr();
			size_t size = section.size();
			this->insert_symbol(Bean::TLS::trans_addr(address, section.tls()), 0, nullptr, section.name(), section.writeable(), section.executable());

			// Find calls in exec
			if (section.executable()) {
				const uint8_t * data = reinterpret_cast<const uint8_t *>(section.data());
#ifdef BEAN_VERBOSE
				// For better readability, name the PLT functions
				bool plt_name = this->debug && String::compare(section.name(), ".plt.", 5) == 0;
#endif
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
								assert(section.executable());
								this->insert_symbol(Bean::TLS::trans_addr(start, section.tls()), 0, nullptr, section.name(), section.writeable(), section.executable(), Elf::STT_FUNC);
								ret = false;
							}
							break;

						default:
							ret = false;
							break;
					}

					for (size_t g = 0; g < insn->detail->groups_count; g++) {
						switch (insn->detail->groups[g]) {
#ifdef BEAN_VERBOSE
							case CS_GRP_JUMP:
								if (plt_name) {
									assert(insn->detail->x86.op_count == 1);
									auto & op = insn->detail->x86.operands[0];
									assert(op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP);

									const auto relocation = this->relocations.find(insn->address + insn->size + op.mem.disp);
									assert(relocation);
									if (relocation->symbol_index() != 0) {
										auto name = relocation->symbol().name();

										auto pos = this->symbols.find(start);
										if (pos)
											pos->name = name;
										else {
											auto sec = this->sections.floor(start);
											assert(sec);
											assert(section.executable());
											this->symbols.emplace(start, Bean::TLS::trans_addr(address - start, sec->tls()), name, sec->name(), sec->writeable(), sec->executable());
										}
									}
								}
								break;
#endif
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
								const auto section = this->sections.floor(target);
								if (section && section->executable())
									this->insert_symbol(Bean::TLS::trans_addr(target, section->tls()), 0, nullptr, section->name(), section->writeable(), true, Elf::STT_FUNC);

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
	}

 private:
	static bool is_branch_instruction(unsigned int instruction) {
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

#ifdef BEAN_VERBOSE
	/*! \brief Helper to identify used operands in `hash_internal` debug output */
	struct HashInternalOpDebug {
		bool hashed = true;
		bool relocation = false;
		uintptr_t value = 0;
	};

	/*! \brief Write debug stream for functions (= symbols in executable sections)
	 * with dissassembled instructions
	 */
	void hash_internal_debug_executable(size_t prefix_size, size_t opcode_size, int debug_ignore, HashInternalOpDebug * op_debug) {
		this->debug_stream << setfill(' ') << setw(16) << prefix << right << hex << insn->address << ' ' << setfill('0') << noprefix;
		auto & detail_x86 = insn->detail->x86;
		int op = 0;
		size_t op_size = 0;
		for (size_t i = 0; i < 12; i++) {
			if (i < insn->size) {
				this->debug_stream << ' ';
				if (i < prefix_size)
					this->debug_stream << "\e[34;3m";
				else if (i < prefix_size + opcode_size)
					this->debug_stream << "\e[34m";
				else if (i >= prefix_size + opcode_size + debug_ignore)
					// This is not necessarly accurate - depending on the encoding
					// however it is only for hash visualization, the real hash uses the disassembled inormation instead of the machine code bytes
					this->debug_stream << "\e[35m";
				else
					this->debug_stream << "\e[36m";
				this->debug_stream << setw(2) << static_cast<int>(insn->bytes[i]) << "\e[0m";
			} else {
				this->debug_stream << "   ";
			}
		}
		// TODO: Not every op is separated by a space...
		this->debug_stream << "\e[34m" << insn->mnemonic << "\e[0m ";
		auto ops = String::split_inplace(insn->op_str, ',');
		assert(ops.size() <= detail_x86.op_count);
		for (size_t o = 0; o < ops.size(); o++) {
			if (o > 0)
				this->debug_stream << "\e[36m,";
			if (!op_debug[o].hashed)
				this->debug_stream << "\e[35m";
			else if (o == 0)
				this->debug_stream << "\e[36m";
			this->debug_stream << ops[o] << "\e[0m";
		}

		// Additional information for reference operands
		bool hashtag = false;
		for (int o = 0; o < detail_x86.op_count; o++) {
			auto & op = op_debug[o];
			if (op.value != 0) {
				this->debug_stream << (hashtag ? "  " : "  # ");
				hashtag = true;
				if (op.hashed)
					this->debug_stream << "\e[3m";
				Bean::dump_address(this->debug_stream, op.value, this->symbols);
				if (op.hashed)
					this->debug_stream << "\e[0m";

				// Check if target is a relocated value (GOT)
				const auto relocation = this->relocations.find(op.value);
				if (relocation != this->relocations.end()) {
					assert(relocation->valid());

					this->debug_stream << " \e[3m[";
					if (relocation->symbol_index() == 0) {
						// No Symbol - calculate target value and add as reference
						Bean::dump_address(this->debug_stream, Relocator(*relocation).value(0), this->symbols);
					} else {
						// Get relocation symbol
						const auto rel_sym = relocation->symbol();
						if (rel_sym.section_index() == ELF<C>::SHN_UNDEF)
							this->debug_stream << rel_sym.name();
						else
							this->debug_stream << "0x" << hex << rel_sym.value();
						if (relocation->addend() != 0)
							this->debug_stream << " + " << dec << relocation->addend();
					}
					this->debug_stream << "]\e[0m";
				}
			}
		}
		this->debug_stream << endl;
	}

	/*! \brief Write debug stream for data/bss (= symbols in non-executable sections)
	 */
	void hash_internal_debug_data(Bean::Symbol & sym, const uint8_t * data, bool is_bss) {
		const size_t bytes_per_line = 16;
		// relocations
		auto rel = sym.rels.lowest();
		bool had_rel = false;
		size_t rel_end = 0;

		// ASCII representation
		int is_ascii = 0;
		char ascii[bytes_per_line * 2] = {};
		size_t ascii_size = 0;
		uintptr_t address = Bean::TLS::virt_addr(sym.address);
		for (size_t a = Math::align_down(address, bytes_per_line); a < Math::align_up(address + sym.size, bytes_per_line); a++) {
			if (a % bytes_per_line == 0)
				this->debug_stream << setfill(' ') << setw(16) << prefix << right << hex << a << ' '
				                   << (a < rel_end ? "\e[35;4m" : "\e[33m") << setfill('0') << noprefix;
			if (a < address || a >= address + sym.size) {
				if (rel && a == rel_end)
					this->debug_stream << "\e[0m";
				this->debug_stream << "   ";
				ascii[ascii_size++] = ' ';
			} else {
				if (rel && a == rel_end) {
					this->debug_stream << "\e[0;33m ";
					rel_end = 0;
					++rel;
				} else {
					this->debug_stream << ' ';
				}
				if (rel && a == rel->offset) {
					this->debug_stream << "\e[35;4m";
					had_rel = true;
					rel_end = rel->offset + Relocator<typename ELF<C>::Relocation>::size(rel->type, this->elf.header.machine());
				}
				int val = static_cast<int>(is_bss ? 0 : data[a - address]);
				this->debug_stream << setw(2) << val;
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
				this->debug_stream << "\e[0m";
				if (had_rel) {
					this->debug_stream << "  #";
					for (auto r = sym.rels.ceil(a - bytes_per_line); r && r->offset <= a; ++r ) {
						this->debug_stream << " \e[4m";
						if (r->name != nullptr) {
							this->debug_stream << r->name;
							if (r->addend != 0)
								this->debug_stream << " + " << dec << r->addend;
						} else {
							Bean::dump_address(this->debug_stream, this->resolve_internal_relocations ? r->target : r->addend, this->symbols);
						}
						this->debug_stream << "\e[0m";
					}

					had_rel = false;
				} else if (is_ascii > 0) {
					this->debug_stream << "  \e[3m# ";
					this->debug_stream.write(ascii, ascii_size);
					this->debug_stream << "\e[0m";
				}
				is_ascii = 0;
				ascii_size = 0;
				this->debug_stream << endl;
			}
		}
	}

	/*! \brief Allocate buffer for symbols debug information
	 * with the contents from debug stream
	 */
	void hash_internal_debug_strdup(Bean::Symbol & sym) {
		size_t len = 0;
		const char * buf = this->debug_stream.str(len);
		if (buf != nullptr && len > 0) {
			char * tmp = Memory::alloc<char>(len + 1);
			assert(tmp != nullptr);
			memcpy(tmp, buf, len);
			tmp[len] = '\0';
			sym.debug = tmp;
		}
		// Clear for next symbol
		this->debug_stream.clear();
	}
#endif

 public:
	/*! \brief Create internal identifier
	 * by hashing all position independent bytes
	 */
	void hash_internal() {
		// Iterate over all symbols
		size_t last_addr = SIZE_MAX;
		ByteBuffer<128> hashbuf;

		for (auto & sym : reverse(this->symbols)) {
			// Load corresponding section
			const auto section = this->sections.floor(sym);
			assert(section);

			// Set symbol section flags
			if (sym.section.name == nullptr) {
				sym.section.name = section->name();
				sym.section.executable = section->executable();
				sym.section.writeable = section->writeable();
			}
#ifdef BEAN_VERBOSE
			// Mark GOT in debug
			if (this->debug && sym.address == this->global_offset_table)
				this->debug_stream << "  \e[3m[the global offset table]\e[0m" << endl;
#endif
			// 3a. calculate size (if 0), TODO: ignore nops!
			const size_t max_addr = Math::min(last_addr, Bean::TLS::trans_addr(Math::align_up(section->virt_addr() + section->size(), section->alignment()), section->tls()));
			uintptr_t address = Bean::TLS::virt_addr(sym.address);
			assert(max_addr >= sym.address);
			const size_t max_size = max_addr - sym.address;
			if (max_size > sym.size)
				sym.size = max_size;

			// 3b. generate links (from jmp + call) & hash
			const size_t offset = address - section->virt_addr();
			const uint8_t * data = reinterpret_cast<const uint8_t *>(section->data()) + offset;
			XXHash64 id_internal(0);  // TODO seed
			if (sym.section.executable) {
				// TLS cannot be executable
				assert(!section->tls());

				size_t size = sym.size;
				bool leave = true;
				size_t last_instruction = address;
				size_t max_branch = address;
				while (cs_disasm_iter(cshandle, &data, &size, &address, insn)) {
					switch (insn->id) {
						// Instruction is a null op - ignore
						case X86_INS_NOP:
							continue;

						// Instruction which leave (and do note return like call)
						case X86_INS_JMP:
						case X86_INS_LJMP:
						case X86_INS_RET:
						case X86_INS_RETF:
						case X86_INS_RETFQ:
						case X86_INS_HLT:
						// Quite rare in applications ;)
						case X86_INS_IRET:
						case X86_INS_IRETD:
						case X86_INS_IRETQ:
						case X86_INS_SYSEXIT:
						case X86_INS_SYSRET:
							leave = true;
							break;

						// Instruction does not leave
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
#ifdef BEAN_VERBOSE
					// Helper for debug
					int debug_ignore = 255;
					HashInternalOpDebug op_debug[detail_x86.op_count];
#endif
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
								if (is_branch_instruction(insn->id)) {
#ifdef BEAN_VERBOSE
									op_debug[o].value = target;
#endif
									// Inside symbol?
									if (target >= sym.address && target < sym.address + sym.size) {
										max_branch = target;
										// same symbol, hence just hash
										hashbuf.push(target - sym.address);
									} else {
										// other symbol, add reference
										sym.refs.insert(target);
#ifdef BEAN_VERBOSE
										op_debug[o].hashed = false;
#endif
									}
								} else {
									hashbuf.push(target);
								}
								break;
							}

							case X86_OP_MEM:
								// Handle FS segment (TLS in Linux)
								if (op.mem.segment == X86_REG_FS) {
									auto tls_end = this->tls_segment.has_value() ? Math::align_up(this->tls_segment.value().virt_addr() + this->tls_segment.value().virt_size(), this->tls_segment.value().alignment()) : 0;
									const auto target = Bean::TLS::trans_addr(tls_end + op.mem.disp, true);
									sym.refs.insert(target);
#ifdef BEAN_VERBOSE
									op_debug[o].hashed = false;
									op_debug[o].value = static_cast<uintptr_t>(target);
#endif
								}
								// RIP relative memory access
								if (op.mem.base == X86_REG_RIP) {
									const auto target = insn->address + insn->size + op.mem.disp;
									sym.refs.insert(target);
#ifdef BEAN_VERBOSE
									op_debug[o].hashed = false;
									op_debug[o].value = static_cast<uintptr_t>(target);
#endif
								} else {
									hashbuf.push(op.mem);
								}
								break;

							default:
								break;
						}
#ifdef BEAN_VERBOSE
						if (debug_ignore > o && !op_debug[o].hashed) {
							debug_ignore = o;
							if (o == 0 && detail_x86.modrm != 0)
								debug_ignore++;
						}
#endif
					}
#ifdef BEAN_VERBOSE
					if (this->debug)
						hash_internal_debug_executable(prefix_size, opcode_size, debug_ignore, op_debug);
#endif
					// add instruction hash buffer to hash
					id_internal.add(hashbuf.buffer(), hashbuf.size());

					// check if zero padding after leave (ubuntu builds...)
					if (leave) {
						bool all_zero = true;
						for (size_t z = 0; z < size; z++)
							if (data[z] != 0) {
								all_zero = false;
								break;
							}
						if (all_zero)
							break;
					}
				}

				// If it doesn't end with a leave instruction (ret), or a branch jumps beyond it, we have to link it to the next function (fallthrough)
				if (!leave || max_branch > last_instruction) {
					auto next = this->symbols.ceil(sym.address + sym.size);
					assert(next);
					sym.refs.insert(next->address);
				}
			} else {
				// 3c. Link relocations to (data) symbols
				bool is_bss = section->type() == ELF<C>::SHT_NOBITS;
				typename ELF<C>::Segment &seg = section->tls() ? this->tls_segment.value() : *this->segments.floor(address);
				assert(address + sym.size <= Math::align_up(seg.virt_addr() + seg.virt_size(), seg.alignment()));
				if (address >= seg.virt_addr() + seg.size())
					is_bss = true;

				if (!is_bss) // TODO: Why?
					for (auto relocation = this->relocations.ceil(sym); relocation != this->relocations.end() && relocation->offset() < address + sym.size; ++relocation) {
						auto r = sym.rels.emplace(*relocation, this->resolve_internal_relocations, this->global_offset_table);
						// Add local (internal) relocation as reference
						if (r.second && this->resolve_internal_relocations && !r.first->undefined)
							sym.refs.insert(r.first->target);
					}


				// Symbols of writeable sections (.data) are depending on the alignment of their (virtual) address
				if (sym.section.writeable && (sym.section.flags & Bean::Symbol::Section::SECTION_RELRO) == 0) {
					id_internal.add<uint32_t>(address % this->page_size);
				}

				// Non-executable objects will be fully hashed
				if (is_bss) {
					id_internal.addZeros(sym.size);
				} else {
					// Do not hash content of relocation targets
					auto start = address;
					auto end = address + sym.size;
					// First entry in GOT is pointer to dynamic, second one unused -- ignore both
					if (start == this->global_offset_table)
						start += 2 * sizeof(void*);
					// Check all relocations
					for (const auto &rel : sym.rels) {
						// Get relocation length
						auto len = Relocator<typename ELF<C>::Relocation>::size(rel.type, this->elf.header.machine());
						if (len == 0)
							continue;

						// Hash content before relocation
						if (start < rel.offset)
							id_internal.add(data + (start - address), rel.offset - start);

						// Hash zeros for relocation
						id_internal.addZeros(len);

						start = rel.offset + len;
						assert(start <= end);
					}
					// Add end
					if (start < end)
						id_internal.add(data + (start - address), end - start);
				}
#ifdef BEAN_VERBOSE
				if (this->debug && sym.size > 0)
					hash_internal_debug_data(sym, data, is_bss);
#endif
			}
#ifdef BEAN_VERBOSE
			// Allocate debug buffer
			if (this->debug)
				hash_internal_debug_strdup(sym);
#endif
			// Calculate has
			sym.id.internal = id_internal.hash();

			last_addr = sym.address;
		}

	}

 public:
	/*! \brief Constructor */
	AnalyzeX86(Bean::symtree_t & symbols, const ELF<C> &elf, const ELF<C> * dbgsym, bool resolve_internal_relocations, bool debug, size_t buffer_size)
	 : Analyze<C>(symbols, elf, dbgsym, resolve_internal_relocations, debug, buffer_size) {
		// Prepare disassembler: Open Handle
		assert(elf.header.ident_class() != ELF<C>::ELFCLASSNONE);
		if (::cs_open(CS_ARCH_X86, elf.header.ident_class() == ELF<C>::ELFCLASS32 ? CS_MODE_32 : CS_MODE_64, &cshandle) != CS_ERR_OK)
			assert(false);

		// Set capstone options
		::cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);

		// preallocate instruction buffer
		insn = ::cs_malloc(cshandle);
	}

	/*! \brief Destructor */
	virtual ~AnalyzeX86() {
		// Free capstone instruction buffer
		cs_free(insn, 1);

		// Close capstone handle
		cs_close(&cshandle);
	}
};
