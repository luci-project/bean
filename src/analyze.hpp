#pragma once

#include <dlh/container/optional.hpp>
#include <dlh/container/pair.hpp>
#include <bean/bean.hpp>

template<ELFCLASS C>
class Analyze {
#ifdef BEAN_VERBOSE
	/*! \brief Pointer to buffer for debug stream */
	char * const debug_buffer = nullptr;

 protected:
	/*! \brief Create detailed debug information for every symbol
	 * \note Allocated memory will never be freed!
	 */
	const bool debug;

	/*! \brief Debug string buffer */
	BufferStream debug_stream;

#endif
 protected:
	/*! \brief Container for all detected symbols */
	Bean::symtree_t &symbols;

	/*! \brief ELF file to analyze */
	const ELF<C> &elf;

	/*! \brief Optional ELF debug symbols (stripped into separate file) */
	const ELF<C> * dbgsym;

	/*! \brief Should internal relocations be resolved
	 * \note security risk with irelative!
	 */
	const bool resolve_internal_relocations;

	/*! \brief Temporary container for relevant sections of elf file */
	TreeSet<typename ELF<C>::Section, Bean::SymbolAddressComparison> sections;

	/*! \brief Temporary container for relevant relocations */
	TreeSet<typename ELF<C>::Relocation, Bean::SymbolAddressComparison> relocations;

	/*! \brief Temporary container for relevant load segments of elf file */
	TreeSet<typename ELF<C>::Segment, Bean::SymbolAddressComparison> segments;

	/*! \brief Page size granularity */
	size_t page_size = 0x1000;

	/*! \brief Address of global offset table (GOT) in virt memory */
	uintptr_t global_offset_table = 0;

	/*! \brief Flags by section */
	struct SectionFlag {
		Bean::Symbol::Section::Flags flag;
		size_t start;
		size_t size;
		SectionFlag(Bean::Symbol::Section::Flags flag, size_t start, size_t size) :
			flag(flag), start(start), size(size) {}
	};
	Vector<SectionFlag> section_flags;

	/*! \brief TLS Segment */
	Optional<typename ELF<C>::Segment> tls_segment;

	/*! \brief Constructor */
	Analyze(Bean::symtree_t & symbols, const ELF<C> &elf, const ELF<C> * dbgsym, bool resolve_internal_relocations, bool debug, size_t buffer_size) :
#ifdef BEAN_VERBOSE
	  debug_buffer(debug ? Memory::alloc<char>(buffer_size) : nullptr), debug(debug), debug_stream(debug_buffer, buffer_size),
#endif
	  symbols(symbols), elf(elf), dbgsym(dbgsym), resolve_internal_relocations(resolve_internal_relocations) {
		assert(elf.header.valid());
		(void) debug;
#ifdef BEAN_VERBOSE
		if (debug)
			assert(debug_buffer != nullptr);
#else
		(void) buffer_size;
		assert(!debug && "debug data not available in DIET mode");
#endif
		if (dbgsym != nullptr) {
			assert(dbgsym->header.valid());
			assert(elf.header.ident_class() == dbgsym->header.ident_class());
			assert(elf.header.ident_data() == dbgsym->header.ident_data());
			assert(elf.header.ident_version() == dbgsym->header.ident_version());
			assert(elf.header.ident_abi() == dbgsym->header.ident_abi());
			assert(elf.header.ident_abiversion() == dbgsym->header.ident_abiversion());
			assert(elf.header.type() == dbgsym->header.type());
			assert(elf.header.machine() == dbgsym->header.machine());
			assert(elf.header.version() == dbgsym->header.version());
		}
	}

	/*! \brief Destructor */
	virtual ~Analyze() {
#ifdef BEAN_VERBOSE
		// Free debug buffer (if allocated)
		Memory::free(debug_buffer);
#endif
	}

	/*! \brief Insert (or, if address range is already in use, merge) symbol */
	void insert_symbol(uintptr_t address, size_t size = 0, const char * name = nullptr, const char * section_name = nullptr, bool writeable = false, bool executable = false) {
		assert(!(executable && writeable));
		assert(!(executable && Bean::TLS::is_tls(address)));
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


	/*! \brief Read ELF program header table
	 * Gather page size, GOT and TLS start & end address
	 */
	virtual void read(const typename ELF<C>::template Array<typename ELF<C>::Segment> & elf_segments) {
		// Read Program header table
		for (const auto & segment: elf_segments) {
			switch (segment.type()) {
				case ELF<C>::PT_TLS:
					assert(!tls_segment.has_value());
					tls_segment = segment;
					break;

				case ELF<C>::PT_LOAD:
					// TODO: Required if we would handle 2 MB (huge pages)
					// However, we currently just act as if they were 4K
					/*
					if (page_size < segment.alignment())
						page_size = segment.alignment();
					*/
					segments.insert(segment);
					if (segment.size() < segment.virt_size()) {
						insert_symbol(segment.virt_addr() + segment.size(), 0, nullptr, nullptr, segment.writeable(), segment.executable());
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_NOBITS, segment.virt_addr() + segment.size(), segment.virt_size() - segment.size());
					}
					break;

				case ELF<C>::PT_DYNAMIC:
				{
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_DYNAMIC, segment.virt_addr(), segment.virt_size());
					size_t rel_start = 0;
					size_t rel_size = 0;
					size_t strtab_start = 0;
					size_t strtab_size = 0;
					size_t preinit_array_start = 0;
					size_t preinit_array_size = 0;
					size_t init_array_start = 0;
					size_t init_array_size = 0;
					size_t fini_array_start = 0;
					size_t fini_array_size = 0;
					for (const auto & dyn: segment.get_dynamic())

						switch(dyn.tag()) {
							case ELF<C>::DT_PLTGOT:
								global_offset_table = dyn.value();
								break;

							case ELF<C>::DT_REL:
							case ELF<C>::DT_RELA:
								rel_start = dyn.value();
								break;

							case ELF<C>::DT_RELSZ:
							case ELF<C>::DT_RELASZ:
								rel_size = dyn.value();
								break;

							case ELF<C>::DT_STRTAB:
								strtab_start = dyn.value();
								break;

							case ELF<C>::DT_STRSZ:
								strtab_size = dyn.value();
								break;break;

							case ELF<C>::DT_INIT_ARRAY:
								init_array_start = dyn.value();
								break;

							case ELF<C>::DT_INIT_ARRAYSZ:
								init_array_size = dyn.value();
								break;

							case ELF<C>::DT_PREINIT_ARRAY:
								preinit_array_start = dyn.value();
								break;

							case ELF<C>::DT_PREINIT_ARRAYSZ:
								preinit_array_size = dyn.value();
								break;

							case ELF<C>::DT_FINI_ARRAY:
								fini_array_start = dyn.value();
								break;

							case ELF<C>::DT_FINI_ARRAYSZ:
								fini_array_size = dyn.value();
								break;
							// TODO: Other dynamic entries can be used to insert symbol borders
						}
					if (rel_size != 0 )
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_RELOC, rel_start, rel_size);
					if (strtab_size != 0 )
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_STRTAB, strtab_start, strtab_size);
					if (preinit_array_size != 0 )
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_INIT, preinit_array_start, preinit_array_size);
					if (init_array_size != 0 )
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_INIT, init_array_start, init_array_size);
					if (fini_array_size != 0 )
						section_flags.emplace_back(Bean::Symbol::Section::SECTION_FINI, fini_array_start, fini_array_size);
					break;
				}

				case ELF<C>::PT_NOTE:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_NOTE, segment.virt_addr(), segment.virt_size());
					break;

				case ELF<C>::PT_GNU_RELRO:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_RELRO, segment.virt_addr(), segment.virt_size());
					insert_symbol(segment.virt_addr() + segment.size(), 0, nullptr, nullptr, true, false);
					break;

				case ELF<C>::PT_GNU_EH_FRAME:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_EH_FRAME, segment.virt_addr(), segment.virt_size());
					break;
				// TODO: Other segment entries can be used to insert symbol borders
			}
		}
	}

	/*! \brief Read ELF section header table
	 * Gather sections, relocations and (defined) symbols
	 */
	virtual void read(const typename ELF<C>::template Array<typename ELF<C>::Section> & elf_sections, bool add_sections = true) {
		for (const auto & section: elf_sections) {
			if (section.size() == 0)
				continue;
			else if (section.allocate() && add_sections) {
				// TODO: What if sections overlap?
				sections.insert(section);
				if (strcmp(section.name(), ".init") == 0)
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_INIT, section.virt_addr(), section.size());
				else if (strcmp(section.name(), ".fini") == 0)
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_FINI, section.virt_addr(), section.size());
			}
			switch(section.type()) {
				// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
				case ELF<C>::SHT_REL:
				case ELF<C>::SHT_RELA:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_RELOC, section.virt_addr(), section.size());
					for (const auto & entry : section.get_relocations())
						relocations.emplace(entry);

					break;

				case ELF<C>::SHT_HASH:
				case ELF<C>::SHT_GNU_HASH:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_HASH, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_GNU_VERDEF:
				case ELF<C>::SHT_GNU_VERNEED:
				case ELF<C>::SHT_GNU_VERSYM:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_VERSION, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_INIT_ARRAY:
				case ELF<C>::SHT_PREINIT_ARRAY:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_INIT, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_FINI_ARRAY:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_FINI, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_STRTAB:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_STRTAB, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_DYNAMIC:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_DYNAMIC, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_NOBITS:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_NOBITS, section.virt_addr(), section.size());
					break;

				case ELF<C>::SHT_SYMTAB:
				case ELF<C>::SHT_DYNSYM:
					section_flags.emplace_back(Bean::Symbol::Section::SECTION_RELOC, section.virt_addr(), section.size());
					for (const auto & sym: section.get_symbols()) {
						switch (sym.section_index()) {
							case ELF<C>::SHN_UNDEF:
							case ELF<C>::SHN_ABS:
							case ELF<C>::SHN_COMMON:
							case ELF<C>::SHN_XINDEX:
								break;

							default:
							{
								auto sym_sec = elf_sections[sym.section_index()];
								if (sym.type() == ELF<C>::STT_TLS) {
									assert(sym_sec.tls());
									assert(tls_segment.has_value());
									insert_symbol(Bean::TLS::trans_addr(tls_segment.value().virt_addr() + sym.value(), true), sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								} else {
									assert(!Bean::TLS::is_tls(sym.value()));  // check for address space conflicts
									if (sym.type() != ELF<C>::STT_NOTYPE) {
										assert(sym.value() >= sym_sec.virt_addr());
										assert(sym.value() + sym.size() <= Math::align_up(sym_sec.virt_addr() + sym_sec.size(), sym_sec.alignment()));
									}
									if (sym.value() != 0 && elf_sections[sym.section_index()].allocate())
										insert_symbol(Bean::TLS::trans_addr(sym.value(), sym_sec.tls()), sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								}
							}
						}
					}
					break;

				default:
					continue;
			}
		}
	}

	/*! \brief Mark symbols in relocation read-only section */
	virtual void add_flags() {
		for (auto & sym : symbols)
			for (auto & section_flag : section_flags)
				if (sym.address >= section_flag.start && sym.address + sym.size < section_flag.start + section_flag.size)
					sym.section.flags |= section_flag.flag;

	}

	/*! \brief Additional read operation, arch depending */
	virtual void read() {}

	/*! \brief Find additional function start addresses (if possible) */
	virtual void find_additional_functions() {}

	/*! \brief Create internal identifier
	 * by hashing all position independent bytes
	 */
	virtual void hash_internal() = 0;

	/*! \brief Calculate external hash and set dependencies
	 * The external identifier is generated by hashing
	 *  - all relocations affecting the corresponding symbol and
	 *  - the internal identifier of all references (including offset)
	 */
	virtual void hash_external() {
		for (auto & sym : symbols) {
			if (sym.rels.size() > 0 || sym.refs.size() > 0 ) {
				XXHash64 id_external(0);  // TODO seed
				// Relocations
				for (const auto rel : sym.rels) {
					assert(rel.offset >= Bean::TLS::virt_addr(sym.address));
					id_external.add<uintptr_t>(rel.offset - Bean::TLS::virt_addr(sym.address));
					id_external.add<uintptr_t>(rel.type);
					if (rel.target == 0) {
						// Unresolved target: add full relocation info
						if (rel.name != nullptr && rel.name[0] != '\0')
							id_external.add(rel.name, String::len(rel.name));
						id_external.add<uintptr_t>(rel.addend);
					} else {
						// Resolved target: Just add as reference
						sym.refs.insert(rel.target);
					}
				}

				// References
				for (const auto ref : sym.refs) {
					auto ref_sym = symbols.floor(ref);
					if (ref_sym) {
						// Special case: external symbols in GOT:
						if (ref_sym->address == global_offset_table) {
							// Special case for first three entries:
							//  - got[0] is pointer to _DYNAMIC (and not used in Luci)
							//  - got[1] is pointer to object (assigned in Luci)
							//  - got[2] is resolve function (assigned in Luci)
							if (ref - ref_sym->address < sizeof(void*) * 3) {
								id_external.add<const char*>("GOT-Special");
								id_external.add<uintptr_t>(ref - ref_sym->address);
								continue;
							}
							// We know that there is no struct like access, hence we can directly hash the target.
							auto rel = ref_sym->rels.find(ref);
							if (rel != ref_sym->rels.end() && rel->undefined) {
								id_external.add<uintptr_t>(rel->type);
								id_external.add<const char*>(rel->name);
								id_external.add<uintptr_t>(rel->addend);
								continue;
							}
						}

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
	}

 public:
	/*! \brief Run all analyzation steps */
	virtual void run() {
		// 1. Read symbols and segments from ELF tables
		read(elf.segments);
		read(elf.sections);
		if (dbgsym != nullptr)
			read(dbgsym->sections, false);
		read();

		// 2. Gather (additional) function start addresses by reading call-targets
		find_additional_functions();

		// 2.5: Add symbols flags
		add_flags();

		// 3. Calculate position independent id
		hash_internal();

		// 4. Calculate full id using references & relocations
		hash_external();
	}
};
