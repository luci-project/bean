#pragma once

#include <dlh/stream/buffer.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/stream/string.hpp>
#include <dlh/environ.hpp>
#include <dlh/syscall.hpp>
#include <dlh/file.hpp>

#include <bean/bean.hpp>
#include <bean/helper/debug_sym.hpp>

struct ElfFile {
	const char * path;
	const int fd;
	const size_t size;
	uintptr_t addr;
	const Elf content;

	ElfFile(const char * path, bool ignore_size = false)
	  : path(path),
	    fd(Syscall::open(path, O_RDONLY).value_or_die("Opening file failed")),
	    size(get_size()),
	    addr(Syscall::mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0).value_or_die("Mapping file failed")),
	    content(read_content(ignore_size)) {}

	~ElfFile() {
		// Cleanup
		Syscall::munmap(addr, size).warn_on_error("Unmapping file failed");
		Syscall::close(fd).warn_on_error("Closing file failed");
	}

 private:
	size_t get_size() const {
		// Determine file size
		struct stat sb;
		Syscall::fstat(fd, &sb).value_or_die("Reading file stats failed");
		return sb.st_size;
	}

	Elf read_content(bool ignore_size) const {
		ELF_Ident * ident = reinterpret_cast<ELF_Ident *>(addr);
		if (size < sizeof(ELF_Ident) || !ident->valid()) {
			cerr << "No valid ELF identification header!" << endl;
			Syscall::exit(EXIT_FAILURE);
		} else if (!ident->data_supported()) {
			cerr << "Unsupported encoding!" << endl;
			Syscall::exit(EXIT_FAILURE);
		} else if (ident->elfclass() != Elf::elfclass()) {
			cerr << "Unsupported class!" << endl;
			Syscall::exit(EXIT_FAILURE);
		}
		Elf elf(reinterpret_cast<uintptr_t>(addr));
		if (!elf.valid(ignore_size ? SIZE_MAX : size)) {
			cerr << "No valid ELF file!" << endl;
			Syscall::exit(EXIT_FAILURE);
		}
		return elf;
	}
};

struct BeanFile {
	const ElfFile binary;
	const ElfFile * dbgsym = nullptr;
	char path[PATH_MAX + 1] = { '\0' };

	Bean bean;

	BeanFile(const char * path, bool load_debug_symbols = false, bool resolve_relocations = true, bool debug = false, const char * root = nullptr)
	  : binary(resolve(path, root)),
	    dbgsym(load_debug_symbols ? debug_symbols(root) : nullptr),
	    bean(binary.content, dbgsym != nullptr ? &(dbgsym->content) : nullptr, resolve_relocations, debug) {}

	~BeanFile() {
		// Cleanup
		if (dbgsym != nullptr)
			delete dbgsym;
	}

 private:
	const char * resolve(const char * path, const char * root) {
		if (!File::exists(path) && root != nullptr) {
			BufferStream(this->path, PATH_MAX + 1) << root << (root[String::len(root) - 1] == '/' ? "" : "/") << path;
			cerr << "Got " << this->path << endl;
			if (File::exists(this->path))
				return this->path;
		}
		String::copy(this->path, path, PATH_MAX);
		return this->path;

	}

	ElfFile * debug_symbols(const char * root) {
		const char * debug_path = DebugSymbol(path, root).find(binary.content);
		cerr << "Debug path = " << debug_path <<endl;
		if (debug_path != nullptr)
			return new ElfFile(debug_path, true);

		return nullptr;
	}
};
