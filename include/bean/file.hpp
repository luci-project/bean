#pragma once

#include <dlh/stream/buffer.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/syscall.hpp>

#include <bean/bean.hpp>

struct BeanFile {
	const char * path;
	const int fd;
	const size_t size;
	uintptr_t addr;

	const Elf elf;

	Bean bean;

	BeanFile(const char * path, bool resolve_relocations = true, bool debug = false)
	  : path(path),
	    fd(Syscall::open(path, O_RDONLY).value_or_die("Opening file failed")),
	    size(get_size()),
	    addr(Syscall::mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0).value_or_die("Mapping file failed")),
	    elf(read_elf()),
	    bean(elf, resolve_relocations, debug) {}

	~BeanFile() {
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

	Elf read_elf() const {
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
		if (!elf.valid(size)) {
			cerr << "No valid ELF file!" << endl;
			Syscall::exit(EXIT_FAILURE);
		}
		return elf;
	}
};
