// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

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
		intptr_t addend;

		/*! \brief Resolved target address */
		uintptr_t target;

		/*! \brief the meaning of the relocation type depends on the architecture (although it should be all the same) */
		ELF_Def::Constants::ehdr_machine machine : 16;

		/*! \brief is the target symbol undefined (= extern) */
		bool undefined : 1;

		/*! \brief was the relocation reconstrected by Bean */
		bool reconstructed : 1;

		/*! \brief offset of relocation to begin of instruction (only available if FLAG_RECONSTRUCT_RELOCATIONS is used) */
		uint8_t instruction_offset : 4;

		/*! \brief How does the instruction access the relocation (only available if FLAG_RECONSTRUCT_RELOCATIONS is used) */
		enum AcccesFlags : uint8_t {
			ACCESSFLAG_UNKNOWN      = 0,
			ACCESSFLAG_READ         = 1 << 0,  // Read
			ACCESSFLAG_WRITE        = 1 << 1,  // Write
			ACCESSFLAG_BRANCH       = 1 << 2,  // branching instruction
			ACCESSFLAG_CONDITIONAL  = 1 << 3,  // conditional (branching) instruction
			ACCESSFLAG_LOCAL        = 1 << 4,  // target in function scope
		};
		uint8_t instruction_access : 8;

		/*! \brief Constructor using plain values */
		SymbolRelocation(uintptr_t offset, uintptr_t type, ELF_Def::Constants::ehdr_machine machine, const char * name = nullptr, intptr_t addend = 0, bool undefined = false, uintptr_t target = 0, bool reconstructed = false, uint8_t instruction_access = ACCESSFLAG_UNKNOWN, uint8_t instruction_offset = 0)
		  : offset(offset), type(type), name(name), addend(addend), target(target), machine(machine), undefined(undefined), reconstructed(reconstructed), instruction_offset(instruction_offset), instruction_access(instruction_access) {}

		/*! \brief Constructor using relocation pointer */
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & relocation, ELF_Def::Constants::ehdr_machine machine, bool resolve_target = false, uintptr_t global_offset_table = 0);

		/*! \brief Constructor using relocation pointer */
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & relocation, ELF_Def::Constants::ehdr_machine machine, bool resolve_target = false, uintptr_t global_offset_table = 0);
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

		/*! \brief Symbol type */
		enum Type : uint8_t {
			TYPE_NONE,
			TYPE_OBJECT,
			TYPE_FUNC,
			TYPE_SECTION,
			TYPE_FILE,
			TYPE_COMMON,
			TYPE_TLS,
			TYPE_INDIRECT_FUNC,
			TYPE_UNKNOWN
		} type;

		/*! \brief Symbol bind */
		enum Bind : int8_t {
			BIND_WEAK   = -1,
			BIND_LOCAL  = 0,
			BIND_GLOBAL = 1,
		} bind;

		enum Flags : uint16_t {
			SYMBOL_NONE       = 0,
			SYMBOL_ENTRY      = 1 << 0,
			SYMBOL_TRAMPOLINE = 1 << 1,  // PLT, GOT
			SYMBOL_USING_CET  = 1 << 2,  // Starts with ENDBR64
		};
		uint16_t flags = SYMBOL_NONE;
		static_assert(sizeof(Flags) == sizeof(flags), "Wrong flags size");

		/*! \brief Section information */
		struct Section {
			/*! \brief Start (virtual) address */
			uintptr_t address;

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
				return this->writeable == that.writeable && this->executable == that.executable && this->flags == that.flags && String::compare(this->name, that.name) == 0;
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
		// todo: include offsets so we are able to compare the stuff

		/*! \brief Relocations affecting this symbol */
		TreeSet<SymbolRelocation, SymbolAddressComparison> rels;

		/*! \brief Hash of instructions until offset (used by relocations) in symbol */
		HashMap<size_t, uint64_t> offset_ids;

		Symbol(uintptr_t address, size_t size, const char * name, uintptr_t section_address, const char * section_name, bool writeable, bool executable, Type type = TYPE_UNKNOWN, Bind bind = BIND_LOCAL, uint16_t flags = Section::SECTION_NONE)
		  : address(address), size(size), name(name), type(type), bind(bind), flags(SYMBOL_NONE), section({section_address, section_name, writeable, executable, flags}), debug(nullptr) {}

		Symbol(const Symbol &) = default;
		Symbol(Symbol &&) = default;

		/*! \brief check if symbol flag is set */
		bool has(Flags flag) const {
			return (flags & flag) != 0;
		}

		void dump_name(BufferStream& bs) const;

		static void dump_header(BufferStream & bs, Verbosity level = VERBOSE);

		void dump(BufferStream & bs, Verbosity level = VERBOSE, const symtree_t * symbols = nullptr, const char * prefix = nullptr) const;

		bool operator==(const Symbol & that) const {
			return this->id == that.id && this->section == that.section && this->refs.size() == that.refs.size() && this->rels.size() == that.rels.size();  // && this->deps.size() == that.deps.size();
		}
	};

	struct SymbolAddressComparison {
		static inline int compare(uintptr_t lhs, uintptr_t rhs) {
			return static_cast<int>(rhs < lhs) - static_cast<int>(lhs < rhs);
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

		static inline bool equal(const Symbol & lhs, const Symbol & rhs) { return lhs.id.internal == rhs.id.internal && lhs.section == rhs.section /* TODO: && lhs.refs.size() == rhs.refs.size() && lhs.rels.size() == rhs.rels.size() */ ; }
	};

	const symtree_t symbols;

	enum Flags : uint32_t {
		FLAG_NONE                         = 0,
		FLAG_DEBUG                        = 1 << 0,
		FLAG_RESOLVE_INTERNAL_RELOCATIONS = 1 << 1,
		FLAG_RECONSTRUCT_RELOCATIONS      = 1 << 2,
		FLAG_KEEP_UNUSED_SYMBOLS          = 1 << 3,
		FLAG_HASH_ATTRIBUTES_FOR_ID       = 1 << 4
	};

	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, const ELF<ELF_Def::Identification::ELFCLASS32> * dbgsym = nullptr, uint32_t flags = 0);
	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, const ELF<ELF_Def::Identification::ELFCLASS64> * dbgsym = nullptr, uint32_t flags = 0);

	static bool diet();
	static uint64_t id_empty();

	void dump(BufferStream & bs, Verbosity level = NONE) const;

	static void dump(BufferStream & bs, const symtree_t & symbols, Verbosity level = NONE);

	template<class T>
	static void dump(BufferStream & bs, const HashSet<Symbol, T> & symbols, Verbosity level = NONE) {
		if (level > NONE) {
			// Sort output by address
			dump(bs, symtree_t(symbols), level);
		} else {
			// unsorted
			for (const auto & sym : symbols)
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
			    && include_dependencies  // check if dependencies should be included
			)
				for (const auto address : sym.deps)
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

	const symtree_t diff(const Bean & other, bool include_dependencies = false, ComparisonMode mode = COMPARE_EXTENDED) const;

	template<class SYMDIFFLIST>
	static bool patchable(const SYMDIFFLIST & diff) {
		uint16_t ignore = Symbol::Section::SECTION_RELRO | Symbol::Section::SECTION_EH_FRAME | Symbol::Section::SECTION_DYNAMIC;
		for (const auto & d : diff) {
			if (d.section.writeable && (d.section.flags & ignore) == 0)
				return false;
			else if (d.section.has(Symbol::Section::SECTION_INIT))
				return false;
		}
		return true;
	}

	bool patchable(const Bean & other, bool include_dependencies = false, ComparisonMode mode = COMPARE_EXTENDED) const {
		return patchable(diff(other, include_dependencies, mode));
	}

	TreeMap<uintptr_t, uintptr_t> map(const Bean & other, bool use_symbol_names = true) const;

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
			for (const auto d : sym->deps)
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
