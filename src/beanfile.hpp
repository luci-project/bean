#pragma once

#include <dlh/stream/buffer.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/unistd.hpp>
#include <dlh/alloc.hpp>

#include <bean/bean.hpp>

struct BeanFile {
	const char * path;
	const int fd;
	const size_t size;
	void * addr;

	const Elf elf;

	Bean bean;

	BeanFile(const char * path, bool resolve_relocations = true, bool debug = false)
	  : path(path),
	    fd(open_file()),
	    size(get_size()),
	    addr(map_memory()),
	    elf(read_elf()),
	    bean(elf, resolve_relocations, debug) {}

	~BeanFile() {
		// Cleanup
		::munmap(addr, size);
		::close(fd);
	}

	static inline bool init() {
		// Capstone (used by Bean) without libc
		cs_opt_mem setup = {
			.malloc = malloc,
			.calloc = calloc,
			.realloc = realloc,
			.free = free,
			.vsnprintf = vsnprintf
		};

		return ::cs_option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&setup)) == 0;
	}

 private:
	int open_file() const {
		// Open file
		int fd = ::open(path, O_RDONLY);
		if (fd == -1) {
			::perror("open");
			exit(EXIT_FAILURE);
		}
		return fd;
	}

	size_t get_size() const {
		// Determine file size
		struct stat sb;
		if (::fstat(fd, &sb) == -1) {
			::perror("fstat");
			::close(fd);
			exit(EXIT_FAILURE);
		}
		return sb.st_size;
	}

	void * map_memory() const {
		// Map file
		void * addr = ::mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (addr == MAP_FAILED) {
			::perror("mmap");
			::close(fd);
			exit(EXIT_FAILURE);
		}
		return addr;
	}

	Elf read_elf() const {
		ELF_Ident * ident = reinterpret_cast<ELF_Ident *>(addr);
		if (size < sizeof(ELF_Ident) || !ident->valid()) {
			cerr << "No valid ELF identification header!" << endl;
			exit(EXIT_FAILURE);
		} else if (!ident->data_supported()) {
			cerr << "Unsupported encoding!" << endl;
			exit(EXIT_FAILURE);
		} else if (ident->elfclass() != Elf::elfclass()) {
			cerr << "Unsupported class!" << endl;
			exit(EXIT_FAILURE);
		}
		Elf elf(reinterpret_cast<uintptr_t>(addr));
		if (!elf.valid(size)) {
			cerr << "No valid ELF file!" << endl;
			exit(EXIT_FAILURE);
		}
		return elf;
	}
};
