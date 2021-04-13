#include <algorithm>
#include <iterator>
#include <iostream>

#include "beanfile.hpp"

struct SymbolSort {
	bool operator()(const Bean::Symbol & a, const Bean::Symbol & b) const { return a.address < b.address; }
};

int main(int argc, const char *argv[]) {
	bool verbose = false;
	bool dependencies = false;
	bool sections = false;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;
	for (int i = 1; i < argc; i++) {
		const std::string arg(argv[i]);
		if (arg == "-v")
			verbose = true;
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
		std::cerr << "Usage: " << argv[0] << "[-v] [-d] FIRST SECOND" << std::endl;
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
			for (auto it = std::make_reverse_iterator(b->bean.symbols.upper_bound(~(section.virt_addr()))); it != b->bean.symbols.rend() && it->first > ~(section.virt_addr() + section.size()); ++it) {
				std::cout << "\e[0m  ";
				if (diff.count(it->second) != 0) {
					std::cout << "\e[33m";
					m++;
				}
				std::cout << std::flush;
				it->second.dump(verbose);
				i++;
			}

			std::cout << "\e[0m(" << i << " symbols";
			if (m > 0)
				std::cout << ", \e[33m" << m << " modified\e[0m";
			std::cout << ")" << std::endl << std::endl;
		}
	} else {
		Bean::dump(diff, verbose);
	}

	delete a;
	delete b;
	return EXIT_SUCCESS;
}
