#pragma once

#include <dlh/utils/xxhash.hpp>
#include <dlh/utils/math.hpp>

#include <bean/bean.hpp>
#include <elfo/elf.hpp>

template<ELFCLASS C>
class Analyze {
	/*! \brief Pointer to buffer for debug stream */
	char * const debug_buffer = nullptr;

 protected:
	/*! \brief Container for all detected symbols */
	Bean::symtree_t &symbols;

	/*! \brief ELF file to analyze */
	const ELF<C> &elf;

	/*! \brief Should internal relocations be resolved
	 * \note security risk with irelative!
	 */
	const bool resolve_internal_relocations;

	/*! \brief Create detailed debug information for every symbol
	 * \note Allocated memory will never be freed!
	 */
	const bool debug;

	/*! \brief Debug string buffer */
	BufferStream debug_stream;

	/*! \brief Temporary container for relevant sections of elf file*/
	TreeSet<typename ELF<C>::Section, Bean::SymbolAddressComparison> sections;

	/*! \brief Temporary container for relevant relocations */
	TreeSet<typename ELF<C>::Relocation, Bean::SymbolAddressComparison> relocations;

	/*! \brief Page size granularity */
	size_t page_size = 0x1000;

	/*! \brief Address of global offset table (GOT) in virt memory */
	uintptr_t global_offset_table = 0;

	/*! \brief Begin of Thread Local Storage (TLS) Image */
	uintptr_t tls_start = 0;

	/*! \brief End of Thread Local Storage (TLS) Image */
	uintptr_t tls_end = 0;

	/*! \brief Constructor */
	Analyze(Bean::symtree_t & symbols, const ELF<C> &elf, bool resolve_internal_relocations, bool debug, size_t buffer_size)
	 : debug_buffer(debug ? reinterpret_cast<char*>(malloc(buffer_size)) : nullptr), symbols(symbols), elf(elf),
	   resolve_internal_relocations(resolve_internal_relocations), debug(debug), debug_stream(debug_buffer, buffer_size) {
		if (debug)
			assert(debug_buffer != nullptr);
	}

	/*! \brief Destructor */
	virtual ~Analyze(){
		// Free debug buffer (if allocated)
		free(debug_buffer);
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
	virtual void read_phdr() {
		// Read Program header table
		for (const auto & segment: elf.segments) {
			switch (segment.type()) {
				case ELF<C>::PT_TLS:
					tls_start = segment.virt_addr();
					tls_end = Math::align_up(segment.virt_addr() + segment.virt_size(), segment.alignment());
					break;

				case ELF<C>::PT_LOAD:
					if (page_size < segment.alignment())
						page_size = segment.alignment();
					break;

				case ELF<C>::PT_DYNAMIC:
					for (const auto & dyn: segment.get_dynamic())
						switch(dyn.tag()) {
							case ELF<C>::DT_PLTGOT:
								global_offset_table = dyn.value();
								break;

							// TODO: Other dynamic entries can be used to insert symbol borders
						}
					break;

				// TODO: Other segment entries can be used to insert symbol borders
			}
		}
	}

	/*! \brief Read ELF section header table
	 * Gather sections, relocations and (defined) symbols
	 */
	virtual void read_shdr() {
		for (const auto & section: elf.sections) {
			if (section.allocate())
				sections.insert(section);
			switch(section.type()) {
				// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
				case ELF<C>::SHT_REL:
				case ELF<C>::SHT_RELA:
					for (const auto & entry : section.get_relocations())
						relocations.emplace(entry);

					break;

				case ELF<C>::SHT_SYMTAB:
				case ELF<C>::SHT_DYNSYM:
					for (const auto & sym: section.get_symbols()) {
						switch (sym.section_index()) {
							case ELF<C>::SHN_UNDEF:
							case ELF<C>::SHN_ABS:
							case ELF<C>::SHN_COMMON:
							case ELF<C>::SHN_XINDEX:
								break;

							default:
							{
								auto sym_sec = elf.sections[sym.section_index()];
								if (sym.type() == ELF<C>::STT_TLS) {
									assert(sym_sec.tls());
									insert_symbol(Bean::TLS::trans_addr(tls_start + sym.value(), true), sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								} else {
									assert(!Bean::TLS::is_tls(sym.value()));  // check for address space conflicts
									if (sym.type() != ELF<C>::STT_NOTYPE) {
										assert(sym.value() >= sym_sec.virt_addr());
										assert(sym.value() + sym.size() <= sym_sec.virt_addr() + sym_sec.size());
									}
									if (sym.value() != 0 && elf.sections[sym.section_index()].allocate())
										insert_symbol(Bean::TLS::trans_addr(sym.value(), sym_sec.tls()), sym.size(), sym.name(), sym_sec.name(), sym_sec.writeable(), sym_sec.executable());
								}
							}
						}
					}
					break;
	/*
				case ELF<C>::SHT_DYNAMIC:
					for (const auto & dyn: section.get_dynamic())
						switch(dyn.tag()) {
							case ELF<C>::DT_PLTGOT:
								global_offset_table = dyn.value();
								break;

							// TODO: Other entries can be used to insert symbol borders
						}
					break;
	*/
				default:
					continue;
			}
		}
	}

	/*! \brief Use Relocation targets (if possible) to identify additional symbols */
	virtual void read_relocations() {}

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
	}

 public:
	/*! \brief Run all analyzation steps */
	virtual void run() {
		// 1. Read symbols and segments from ELF tables
		read_phdr();
		read_shdr();
		read_relocations();

		// 2. Gather (additional) function start addresses by reading call-targets
		find_additional_functions();

		// 3. Calculate position independent id
		hash_internal();

		// 4. Calculate full id using references & relocations
		hash_external();
	}
};
