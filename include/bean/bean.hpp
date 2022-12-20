#pragma once

#include <dlh/container/vector.hpp>
#include <dlh/container/hash.hpp>
#include <dlh/container/tree.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/stream/buffer.hpp>
#include <dlh/bytebuffer.hpp>
#include <dlh/iterator.hpp>
#include <dlh/string.hpp>
#include <dlh/xxhash.hpp>
#include <dlh/math.hpp>

#include <elfo/elf.hpp>

struct Bean {
	/*! \brief To handle TLS symbols, their addresses are extended by an flag, so they can reside in the same address space like the rest
	 * \note This hack only works if no regular address has the `ADDRESS_FLAG` bit set.
	 */
	struct TLS {
		/*! \brief Flag for TLS address */
		static const uintptr_t ADDRESS_FLAG = 0xf0000000000000;

		/*! \brief Translated address, having an flag for TLS address space */
		static inline uintptr_t trans_addr(uintptr_t virt_addr, bool tls) {
			return virt_addr | (tls ? ADDRESS_FLAG : 0);
		}

		/*! \brief get virtual address (e.g. used in ELF for relocation) */
		static inline  uintptr_t virt_addr(uintptr_t trans_addr) {
			return trans_addr & ~ADDRESS_FLAG;
		}

		/*! \brief check if translated address is a TLS address  */
		static inline bool is_tls(uintptr_t trans_addr) {
			return (trans_addr & ADDRESS_FLAG) != 0;
		}
	};

	enum Verbosity : uint8_t {
		NONE,
		VERBOSE,
		DEBUG,
		TRACE
	};

	struct MemArea {
		/*! \brief Start (translated) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Flag for writable symbol */
		bool writeable = false;

		/*! \brief Flag for executable symbol */
		bool executable = false;

		/*! \brief Flag for relocation-readonly symbol */
		uint16_t flags = 0;

		MemArea(uintptr_t address, size_t size, bool writeable, bool executable, uint16_t flags = 0)
		  : address(address), size(size), writeable(writeable), executable(executable), flags(flags) {}

	};

	struct SymbolRelocation {
		/*! \brief Offset in virtual memory for the relocation */
		uintptr_t offset;

		/*! \brief Relocation type (architecture dependend value) */
		uintptr_t type;

		/*! \brief Symbolic name (if available) */
		const char * name;

		/*! \brief Addend for reloaction */
		uintptr_t addend;

		/*! \brief Resolved target address */
		uintptr_t target;

		/*! \brief is the target symbol undefined (= extern) */
		bool undefined;

		/*! \brief Constructor using plain values */
		SymbolRelocation(uintptr_t offset, uintptr_t type, const char * name = nullptr, uintptr_t addend = 0, bool undefined = false, uintptr_t target = 0)
		  : offset(offset), type(type), name(name), addend(addend), target(target), undefined(undefined) {}

		/*! \brief Constructor using relocation pointer */
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & relocation, bool resolve_target = false, uintptr_t global_offset_table = 0);

		/*! \brief Constructor using relocation pointer */
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & relocation, bool resolve_target = false, uintptr_t global_offset_table = 0);
	};

	struct Symbol;
	struct SymbolAddressComparison;
	struct SymbolIdentifierComparison;
	struct SymbolInternalIdentifierComparison;

	typedef TreeSet<Symbol, SymbolAddressComparison> symtree_t;
	typedef HashSet<Symbol, SymbolIdentifierComparison> symhash_t;
	typedef HashSet<Symbol, SymbolInternalIdentifierComparison> syminthash_t;
	typedef Vector<MemArea> memarea_t;

	struct Symbol {
		/*! \brief Start (virtual) address */
		uintptr_t address;

		/*! \brief Size */
		size_t size;

		/*! \brief Symbol name (for debugging) */
		const char * name;

		/*! \brief Symbol bind */
		enum Bind {
			BIND_WEAK   = -1,
			BIND_LOCAL  = 0,
			BIND_GLOBAL = 1,
		} bind;

		/*! \brief Section information */
		struct Section {
			/*! \brief Section name (for debugging) */
			const char * name = nullptr;

			/*! \brief Flag for writable symbol */
			bool writeable = false;

			/*! \brief Flag for executable symbol */
			bool executable = false;

			/*! \brief Flag containing additional section information */
			enum Flags : uint16_t {
				SECTION_NONE     = 0,
				SECTION_RELRO    = 1 <<  0,
				SECTION_NOTE     = 1 <<  1,
				SECTION_DYNAMIC  = 1 <<  2,
				SECTION_VERSION  = 1 <<  3,
				SECTION_INIT     = 1 <<  4,
				SECTION_FINI     = 1 <<  5,
				SECTION_RELOC    = 1 <<  6,
				SECTION_SYMTAB   = 1 <<  7,
				SECTION_STRTAB   = 1 <<  8,
				SECTION_HASH     = 1 <<  9,
				SECTION_EH_FRAME = 1 << 10,
				SECTION_NOBITS   = 1 << 11,
			};
			uint16_t flags = SECTION_NONE;
			static_assert(sizeof(Flags) == sizeof(flags), "Wrong flags size");

			/*! \brief check if section flag is set */
			bool has(Flags flag) const {
				return (flags & flag) != 0;
			}

			/*! \brief check if section parameters match */
			bool operator==(const Section & that) const {
				return this->writeable == that.writeable && this->executable == that.executable && this->flags == that.flags;
			}

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
			void dump(BufferStream& bs) const;

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

		Symbol(uintptr_t address, size_t size, const char * name, const char * section_name, bool writeable, bool executable, Bind bind = BIND_LOCAL, uint16_t flags = Section::SECTION_NONE)
		  : address(address), size(size), name(name), bind(bind), section({section_name, writeable, executable, flags}), debug(nullptr) {}

		Symbol(const Symbol &) = default;
		Symbol(Symbol &&) = default;
		Symbol & operator=(const Symbol &) = default;
		Symbol & operator=(Symbol &&) = default;

		void dump_name(BufferStream& bs) const;

		static void dump_header(BufferStream & bs, Verbosity level = VERBOSE);

		void dump(BufferStream & bs, Verbosity level = VERBOSE, const symtree_t * symbols = nullptr, const char * prefix = nullptr) const;

		bool operator==(const Symbol & that) const {
			return this->id == that.id && this->section == that.section && this->refs.size() == that.refs.size() && this->rels.size() == that.rels.size(); // && this->deps.size() == that.deps.size();
		}
	};

	struct SymbolAddressComparison {
		static inline int compare(uintptr_t lhs, uintptr_t rhs) {
			return (rhs < lhs) - (lhs < rhs);
		}

		static inline int compare(const Symbol & lhs, const Symbol & rhs) { return compare(lhs.address, rhs.address); }
		static inline int compare(uintptr_t lhs, const Symbol & rhs) { return compare(lhs, rhs.address); }
		static inline int compare(const Symbol & lhs, uintptr_t rhs) { return compare(lhs.address, rhs); }

		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & rhs) { return compare(lhs.address, TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & rhs) { return compare(lhs.address, TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & lhs, const Symbol & rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), rhs.address); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & lhs, const Symbol & rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), rhs.address); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & rhs) { return compare(lhs, TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & rhs) { return compare(lhs, TLS::trans_addr(rhs.virt_addr(), rhs.tls())); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Section & lhs, uintptr_t rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), rhs); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Section & lhs, uintptr_t rhs) { return compare(TLS::trans_addr(lhs.virt_addr(), lhs.tls()), rhs); }

		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & rhs) { return compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & rhs) { return compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & rhs) { return compare(TLS::virt_addr(lhs.address), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & rhs) { return compare(TLS::virt_addr(lhs.address), rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & lhs, const Symbol & rhs) { return compare(lhs.offset(), TLS::virt_addr(rhs.address)); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & lhs, const Symbol & rhs) { return compare(lhs.offset(), TLS::virt_addr(rhs.address)); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & rhs) { return compare(lhs, rhs.offset()); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & rhs) { return compare(lhs, rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Segment & lhs, uintptr_t rhs) { return compare(lhs.offset(), rhs); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Segment & lhs, uintptr_t rhs) { return compare(lhs.offset(), rhs); }

		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & rhs) { return compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & rhs) { return compare(lhs.offset(), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & rhs) { return compare(TLS::virt_addr(lhs.address), rhs.offset()); }
		static inline int compare(const Symbol & lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & rhs) { return compare(TLS::virt_addr(lhs.address), rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & lhs, const Symbol & rhs) { return compare(lhs.offset(), TLS::virt_addr(rhs.address)); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & lhs, const Symbol & rhs) { return compare(lhs.offset(), TLS::virt_addr(rhs.address)); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & rhs) { return compare(lhs, rhs.offset()); }
		static inline int compare(uintptr_t lhs, const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & rhs) { return compare(lhs, rhs.offset()); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & lhs, uintptr_t rhs) { return compare(lhs.offset(), rhs); }
		static inline int compare(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & lhs, uintptr_t rhs) { return compare(lhs.offset(), rhs); }

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

	struct SymbolInternalIdentifierComparison: public Comparison {
		using Comparison::equal;
		using Comparison::hash;

		static inline uint32_t hash(const Symbol& sym) { return Comparison::hash(sym.id.internal); }

		static inline bool equal(const Symbol & lhs, const Symbol & rhs) { return lhs.id.internal == rhs.id.internal && lhs.section == rhs.section && lhs.refs.size() == rhs.refs.size() && lhs.rels.size() == rhs.rels.size(); }
	};

	const symtree_t symbols;

	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, const ELF<ELF_Def::Identification::ELFCLASS32> * dbgsym = nullptr, bool resolve_internal_relocations = true, bool debug = false, size_t buffer_size = 1048576);
	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, const ELF<ELF_Def::Identification::ELFCLASS64> * dbgsym = nullptr, bool resolve_internal_relocations = true, bool debug = false, size_t buffer_size = 1048576);

	void dump(BufferStream & bs, Verbosity level = NONE) const;

	static void dump(BufferStream & bs, const symtree_t & symbols, Verbosity level = NONE);

	template<class T>
	static void dump(BufferStream & bs, const HashSet<Symbol, T> & symbols, Verbosity level = NONE) {
		if (level > NONE) {
			// Sort output by address
			dump(bs, symtree_t(symbols), level);
		} else {
			// unsorted
			for (const auto & sym: symbols)
				sym.dump(bs, level);
		}
	}

	static symtree_t::ConstIterator dump_address(BufferStream & bs, uintptr_t value, const symtree_t & symbols);

	template<class T>
	const HashSet<Symbol, T> diff(const HashSet<Symbol, T> & other_symbols, bool include_dependencies = false, bool (*skip)(const Symbol &) = nullptr) const {
		HashSet<Symbol, T> result;
		for (const auto & sym : symbols)
			if (skip != nullptr && skip(sym))
				continue;
			else if (!other_symbols.contains(sym)  // find symbols which hash does not exist in other binary
			    && sym.size > 0  // ignore symbols without size (they are only markers like __end)
			    && result.insert(sym).second  // skip if already added
			    && include_dependencies // check if dependencies should be included
			)
				for (const auto address: sym.deps)
					dependencies(address, result);
		return result;
	}

	const symhash_t diff_extended(const Bean & other, bool include_dependencies = false, bool (*skip)(const Symbol &) = nullptr) const {
		return diff(symhash_t(other.symbols), include_dependencies, skip);
	}

	const syminthash_t diff_internal(const Bean & other, bool include_dependencies = false, bool (*skip)(const Symbol &) = nullptr) const {
		return diff(syminthash_t(other.symbols), include_dependencies, skip);
	}

	enum ComparisonMode {
		// Check both internal and extrnal hash, for all symbols
		COMPARE_EXTENDED = 0,
		// Check both internal and extrnal hash, except for writable symbols (use only internal for them)
		COMPARE_WRITEABLE_INTERNAL = 1,
		// Check only internal hash, except for executable section (use both for them)
		COMPARE_EXECUTABLE_EXTENDED = 2,
		// Check only internal hash, for all symbols
		COMPARE_ONLY_INTERNAL = 3
	};

	const symtree_t diff(const Bean & other, bool include_dependencies = false, ComparisonMode mode = COMPARE_EXTENDED,  bool * patchable = nullptr) const;

	bool patchable(const Bean & other, bool include_dependencies = false, ComparisonMode mode = COMPARE_EXTENDED) const;

	template<class T>
	static bool patchable(const HashSet<Symbol, T> & diff) {
		uint16_t ignore = Symbol::Section::SECTION_RELRO | Symbol::Section::SECTION_EH_FRAME | Symbol::Section::SECTION_DYNAMIC;
		for (const auto & d : diff)
			if (d.section.writeable && (d.section.flags & ignore) == 0)
				return false;
			else if (d.section.has(Symbol::Section::SECTION_INIT))
				return false;
		return true;
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
	template<class T>
	void dependencies(uintptr_t address, HashSet<Symbol, T> & result) const {
		auto sym = symbols.ceil(address);
		// if symbol was found and not yet part of the result list, add and check all symbols depending on this one
		if (sym && sym->size > 0 && sym->section.executable && result.emplace(*sym).second)
			for (const auto d: sym->deps)
				dependencies(d, result);
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
