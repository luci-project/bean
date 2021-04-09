#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fcntl.h>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#include <iomanip>

#include <vector>

#include <capstone/capstone.h>
#include "elf.hpp"
#include "xxhash64.h"

struct Symbol {
	uintptr_t address; // virt!
	size_t size;
	size_t section_index;
	uint8_t type, bind;
	const char * name = nullptr;
	// ToDo: Version?
	uint64_t id = 0; // standalone hash
	std::vector<uintptr_t> refs;
};

template<ELFCLASS C>
static bool readelf(void * addr, size_t length) {
	ELF<C> elf(reinterpret_cast<uintptr_t>(addr));
	if (!elf.valid(length)) {
		std::cerr << "No valid 32-bit ELF file!" << std::endl;
		return false;
	}

	// Gather all information
	std::vector<Symbol> contents;
	std::vector<size_t> text_data;
	for (auto & section: elf.sections)
		switch(section.type()) {
			case ELF<C>::SHT_PROGBITS:
			case ELF<C>::SHT_INIT_ARRAY:
			case ELF<C>::SHT_FINI_ARRAY:
			case ELF<C>::SHT_PREINIT_ARRAY:
				if (section.allocate())
					text_data.push_back(elf.sections.index(section));
				break;

			// TODO: Read relocations, since they need to be compared as well (especially undefined ones...)
			case ELF<C>::SHT_REL:
				// TODO: relocations<typename ELF<C>::Relocation>(section);
				break;
			case ELF<C>::SHT_RELA:
				// TODO: relocations<typename ELF<C>::RelocationWithAddend>(section);
				break;

			case ELF<C>::SHT_SYMTAB:
			case ELF<C>::SHT_DYNSYM:
				for (auto & sym: section.get_symbols())
					switch (sym.section_index()) {
						case ELF<C>::SHN_UNDEF:
						case ELF<C>::SHN_ABS:
						case ELF<C>::SHN_COMMON:
						case ELF<C>::SHN_XINDEX:
							break;

						default:
							if (sym.size() > 0) // TODO: we could later try to calculate the real size...
								contents.push_back({
									.address = sym.value(),
									.size = sym.size(),
									.section_index = sym.section_index(),
									.type = static_cast<uint8_t>(sym.type()),
									.bind = static_cast<uint8_t>(sym.bind()),
									.name = sym.name()
								});
					}
				break;

			default:
				continue;
		}

	/*! TODO:
	 * 1. Put into interval tree structure
	 * 2. For all symbols with size == 0 try to expand until end of section or next symbol?
	 * 3. Visit alle code parts not covered by any symbol, if not NOP, create new temporary Symbol
	 * 4. Merge overlapping symbols (priority to dynsym or something similar)
	 */
	csh cshandle;
	if (::cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
		return false;
	::cs_option(cshandle, CS_OPT_DETAIL, CS_OPT_ON);

	for (const auto & section_index : text_data) {
		auto section = elf.sections[section_index];
		// Todo: use interval tree!
		for (auto & sym : contents) {
			if (sym.section_index != section_index)
				continue;
			// We are working on file data only
			const uint8_t * data = reinterpret_cast<const uint8_t*>(sym.address - section.virt_addr() + reinterpret_cast<uintptr_t>(section.data()));

			// TODO: Relocations -> add link

			XXHash64 symhash(0);  // TODO: Seed on file name?
			printf("%s @ %s", sym.name, section.name());
			if (sym.type == ELF<C>::STT_FUNC) {
				cs_insn *insn;
				size_t count = ::cs_disasm(cshandle, data, sym.size, sym.address, 0, &insn);
				printf(" (%lu instructions)\n", count);

				if (count > 0) {

					for (size_t j = 0; j < count; j++) {
						printf("0x%lx:  %s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
						if (insn[j].detail->x86.disp != 0) {
							printf("          ID: %d\n", insn[j].id);
							printf("        Size: %d\n", insn[j].size);
							printf("      Prefix: %02x %02x %02x %02x\n", insn[j].detail->x86.prefix[0], insn[j].detail->x86.prefix[1], insn[j].detail->x86.prefix[2], insn[j].detail->x86.prefix[3]);
							printf("      Opcode: %02x %02x %02x %02x\n", insn[j].detail->x86.opcode[0], insn[j].detail->x86.opcode[1], insn[j].detail->x86.opcode[2], insn[j].detail->x86.opcode[3]);
							printf("         REX: %02x\n", insn[j].detail->x86.rex);
							printf("    addrsize: %02x\n", insn[j].detail->x86.addr_size);
							printf("       modrm: %02x\n", insn[j].detail->x86.modrm);
							printf("        disp: %ld\n", insn[j].detail->x86.disp);
						}
						// if disp is beyond function border, add link and hash disp with zero
						auto target = insn[j].address + insn[j].size + insn[j].detail->x86.disp;
						if (target < sym.address || target > sym.address + sym.size) {
							symhash.add(&(insn[j].detail->x86), 12);
							// TODO: Link
							printf("LINK!\n");
						} else {
							symhash.add(&(insn[j].detail->x86), 20);
						}
					}
					::cs_free(insn, count);
				} else {
					printf("ERROR: Failed to disassemble given code!\n");
				}
			} else {
				// Data
				printf(" (%lu bytes)", sym.size);
				for (size_t i = 0; i < sym.size; i++) {
					if (i % 16 == 0)
						printf("\n%lx\t", sym.address + i);
					printf(" %02x", data[i]);
				}
				printf("\n");
				symhash.add(data, sym.size);
			}
			// Calculate hash
			sym.id = symhash.hash();
			printf(" [id: %0lX]\n\n", sym.id);
		}
	}
	return true;
}

static bool readelf(void * addr, size_t length) {
	// Read ELF Identification
	ELF_Ident * ident = reinterpret_cast<ELF_Ident *>(addr);
	if (length < sizeof(ELF_Ident) || !ident->valid()) {
		std::cerr << "No valid ELF identification header!" << std::endl;
		return false;
	} else if (!ident->data_supported()) {
		std::cerr << "Unsupported encoding (must be " << ident->data_host() << ")!" << std::endl;
		return false;
	} else {
		switch (ident->elfclass()) {
			case ELFCLASS::ELFCLASS32:
				return readelf<ELFCLASS::ELFCLASS32>(addr, length);

			case ELFCLASS::ELFCLASS64:
				return readelf<ELFCLASS::ELFCLASS64>(addr, length);

			default:
				std::cerr << "Unsupported class!" << std::endl;
				return false;
		}
	}
}

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " ELF-FILE" << std::endl;
		return EXIT_FAILURE;
	}

	// Open file
	int fd = ::open(argv[1], O_RDONLY);
	if (fd == -1) {
		::perror("open");
		return EXIT_FAILURE;
	}

	// Determine file size
	struct stat sb;
	if (::fstat(fd, &sb) == -1) {
		::perror("fstat");
		::close(fd);
		return EXIT_FAILURE;
	}
	size_t length = sb.st_size;

	// Map file
	void * addr = ::mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		::perror("mmap");
		::close(fd);
		return EXIT_FAILURE;
	}

	bool success = readelf(addr, length);

	// Cleanup
	::munmap(addr, length);
	::close(fd);
	return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
