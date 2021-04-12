#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fcntl.h>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <iomanip>

#include "bean.hpp"

struct ElfFile {
	const char * path;
	const int fd;
	const size_t size;
	void * addr;

	Elf elf;

	Bean bean;

	ElfFile(const char * path)
	  : path(path),
	    fd(open_file()),
	    size(get_size()),
	    addr(map_memory()),
	    elf(read_elf()),
	    bean(elf) {}

	~ElfFile() {
		// Cleanup
		::munmap(addr, size);
		::close(fd);
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
			std::cerr << "No valid ELF identification header!" << std::endl;
			exit(EXIT_FAILURE);
		} else if (!ident->data_supported()) {
			std::cerr << "Unsupported encoding!" << std::endl;
			exit(EXIT_FAILURE);
		} else if (ident->elfclass() != Elf::elfclass()) {
			std::cerr << "Unsupported class!" << std::endl;
			exit(EXIT_FAILURE);
		}
		Elf elf(reinterpret_cast<uintptr_t>(addr));
		if (!elf.valid(size)) {
			std::cerr << "No valid ELF file!" << std::endl;
			exit(EXIT_FAILURE);
		}
		return elf;
	}
};

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " ELF-FILES" << std::endl;
		return EXIT_FAILURE;
	}

	std::vector<ElfFile> files;
	for (int i = 1; i < argc; i++) {
		files.emplace_back(argv[i]);
	}

	for (auto file : files) {
		file.bean.dump();
	}

	return EXIT_SUCCESS;
}
