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

		// Explicit instantiation
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS32>::Relocation & relocation, bool resolve_target = false, uintptr_t global_offset_table = 0);
		SymbolRelocation(const typename ELF<ELF_Def::Identification::ELFCLASS64>::Relocation & relocation, bool resolve_target = false, uintptr_t global_offset_table = 0);
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

		Symbol(uintptr_t address, size_t size, const char * name, const char * section_name, bool writeable, bool executable)
		  : address(address), size(size), name(name), section({section_name, writeable, executable}), debug(nullptr) {}

		Symbol(const Symbol &) = default;
		Symbol(Symbol &&) = default;
		Symbol & operator=(const Symbol &) = default;
		Symbol & operator=(Symbol &&) = default;

		void dump_name(BufferStream& bs) const;

		static void dump_header(BufferStream & bs, Verbosity level = VERBOSE);

		void dump(BufferStream & bs, Verbosity level = VERBOSE, const symtree_t * symbols = nullptr, const char * prefix = nullptr) const;

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

	const symtree_t symbols;

	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS32> & elf, bool resolve_internal_relocations = true, bool debug = false, size_t buffer_size = 1048576);
	explicit Bean(const ELF<ELF_Def::Identification::ELFCLASS64> & elf, bool resolve_internal_relocations = true, bool debug = false, size_t buffer_size = 1048576);

	void dump(BufferStream & bs, Verbosity level = NONE) const;

	static void dump(BufferStream & bs, const symtree_t & symbols, Verbosity level = NONE);

	static void dump(BufferStream & bs, const symhash_t & symbols, Verbosity level = NONE);

	static symtree_t::ConstIterator dump_address(BufferStream & bs, uintptr_t value, const symtree_t & symbols);

	/*! \brief Merge memory areas */
	const memarea_t merge(const symtree_t & symbols, size_t threshold = 0) const;

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

	const symhash_t diff(const symhash_t & other_symbols, bool include_dependencies = false) const;

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
	void dependencies(uintptr_t address, symhash_t & result) const;
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
