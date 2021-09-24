#pragma once

#include <dlh/stream/buffer.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/stream/string.hpp>
#include <dlh/syscall.hpp>
#include <dlh/file.hpp>

#include <bean/bean.hpp>

struct ElfFile {
	const char * path;
	const int fd;
	const size_t size;
	uintptr_t addr;
	const Elf content;

	ElfFile(const char * path)
	  : path(path),
	    fd(Syscall::open(path, O_RDONLY).value_or_die("Opening file failed")),
	    size(get_size()),
	    addr(Syscall::mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0).value_or_die("Mapping file failed")),
	    content(read_content()) {}

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

	Elf read_content() const {
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

struct BeanFile {
	const ElfFile binary;
	const ElfFile * dbgsym;

	Bean bean;

	BeanFile(const char * path, bool load_debug_symbols = false, bool resolve_relocations = true, bool debug = false)
	  : binary(path),
	    dbgsym(load_debug_symbols ? find_debug_symbols() : nullptr),
	    bean(binary.content, dbgsym != nullptr ? &(dbgsym->content) : nullptr, resolve_relocations, debug) {}

	~BeanFile() {
		// Cleanup
		if (dbgsym != nullptr)
			delete dbgsym;
	}

 private:
	ElfFile * find_debug_symbols() {
		if (!binary.content.header.valid() || binary.content.header.type() == Elf::ET_CORE)
			return nullptr;

		StringStream<PATH_MAX + 1> path;

		// check debug symbol using build ID
		for (auto & section: binary.content.sections)
			if (section.type() == Elf::SHT_NOTE)
				for (auto & note : section.get_notes())
					if (note.name() != nullptr && strcmp(note.name(), "GNU") == 0 && note.type() == Elf::NT_GNU_BUILD_ID) {
							auto desc = reinterpret_cast<const uint8_t *>(note.description());
							path << "/usr/lib/debug/.build-id/" << hex << right << setfill('0') << setw(2) << static_cast<uint32_t>(desc[0]) << '/';
							for (size_t i = 1; i < note.size(); i++)
								path << hex << right << setfill('0') << setw(2)  << static_cast<uint32_t>(desc[i]);
							path << ".debug";
							if (File::readable(path.str()))
								return new ElfFile(path.str());
							path.clear();
					}

		// Debug link
		char binpath[PATH_MAX + 1];
		if (File::absolute(binary.path, binpath, PATH_MAX + 1)) {
			// Same directory
			path << binpath << ".debug";
			if (File::readable(path.str()))
				return new ElfFile(path.str());
			path.clear();

			// In a subdirectory called ".debug/"
			char * slash = String::find_last(binpath, '/');
			if (slash != nullptr) {
				path.write(binpath, slash - binpath);
				path << "/.debug" << slash << ".debug";
				if (File::readable(path.str()))
					return new ElfFile(path.str());
				path.clear();
			}

			// With path as subdirectory in global debug folder
			path << "/usr/lib/debug" << binpath << ".debug";
			if (File::readable(path.str()))
				return new ElfFile(path.str());
		}

		cerr << "No debug symbols for " << binpath << " found..." << endl;
		return nullptr;
	}
};
