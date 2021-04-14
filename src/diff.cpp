#include <algorithm>
#include <iterator>
#include <iostream>

#include "beanfile.hpp"

struct SymbolSort {
	bool operator()(const Bean::Symbol & a, const Bean::Symbol & b) const { return a.address < b.address; }
};

int main(int argc, const char *argv[]) {
	unsigned verbose = 0;
	bool dependencies = false;
	bool sections = false;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;
	for (int i = 1; i < argc; i++) {
		const std::string arg(argv[i]);
		if (arg == "-v")
			verbose = 1;
		else if (arg == "-vv")
			verbose = 2;
		else if (arg == "-d")
			dependencies = true;
		else if (arg == "-s")
			sections = true;
		else if (a == nullptr)
			a = new BeanFile(argv[i]);
		else if (b == nullptr)
			b = new BeanFile(argv[i]);
		else
			std::cerr << "Ignoring argument " << arg << std::endl;
	}

	if (b == nullptr) {
		delete a;
		std::cerr << "Usage: " << argv[0] << "[-v[v]] [-d] FIRST SECOND" << std::endl;
		return EXIT_FAILURE;
	}

	auto & diff = b->bean.diff(a->bean, dependencies);
	if (sections) {
		std::cout << "File " << b->path << std::endl;
		for (const auto & section : b->bean.elf.sections) {
			std::cout << "\e[1m"
			          << "[" << b->bean.elf.sections.index(section) << "] "
			          << section.name()
			          << "\e[0m";
			if (section.allocate()) {
				std::cout << " @ 0x" << std::hex << section.virt_addr()
				          << " (" << std::dec << section.size() << " Bytes)"
				          << " A";
			} else {
				std::cout << std::endl;
				continue;
			}
			if (section.writeable())
				std::cout << "W";
			if (section.executable())
				std::cout << "X";
			std::cout << ":" << std::endl;

			size_t i = 0, m = 0;
			const auto begin = b->bean.find(section.virt_addr());
			const auto end = b->bean.find(section.virt_addr() + section.size());
			for (auto it = begin; it != end; ++it) {
				std::cout << "\e[0m  ";
				if (diff.count(*it) != 0) {
					std::cout << "\e[33m";
					m++;
				}
				std::cout << std::flush;
				it->dump(verbose != 0);
				if (verbose == 2) {
					// refs
					bool header = false;
					for (const auto raddress : it->refs) {
						std::cout << (!header ? "      using " : "            ");
						header = true;
						auto rsym = b->bean.get(raddress);

						if (rsym == nullptr) {
							std::cout << "0x" << std::hex << raddress << std::dec << " [unresolved]";
						} else {
							std::cout << "0x" << std::hex << rsym->address << std::dec;
							if (raddress != rsym->address)
								std::cout << " + " << (raddress - rsym->address);
							if (rsym->name != nullptr)
								std::cout << " (" << rsym->name << ")";
						}
						std::cout << std::endl;
					}
					// deps
					header = false;
					for (const auto daddress : it->deps) {
						std::cout << (!header ? "    used by " : "            ");
						header = true;
						auto dsym = b->bean.get(daddress);

						if (dsym == nullptr) {
							std::cout << "0x" << std::hex << daddress << std::dec << " [unresolved]";
						} else {
							std::cout << "0x" << std::hex << dsym->address << std::dec;
							if (dsym->name != nullptr)
								std::cout << " (" << dsym->name << ")";
						}
						std::cout << std::endl;
					}
					std::cout << std::endl;
				}
				i++;
			}

			std::cout << "\e[0m(" << i << " symbols";
			if (m > 0)
				std::cout << ", \e[33m" << m << " modified\e[0m";
			std::cout << ")" << std::endl << std::endl;
		}
	} else {
		Bean::dump(diff, verbose != 0);
	}

	delete a;
	delete b;
	return EXIT_SUCCESS;
}
