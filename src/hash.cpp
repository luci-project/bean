#include <iostream>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << "[-r] [-v] [-x] ELF-FILES" << std::endl;
		return EXIT_FAILURE;
	}

	bool verbose = false;
	bool reloc = false;
	bool explain = false;
	std::vector<BeanFile> files;
	for (int i = 1; i < argc; i++) {
		if (std::string(argv[i]) == "-r")
			reloc = true;
		else if (std::string(argv[i]) == "-v")
			verbose = true;
		else if (std::string(argv[i]) == "-x")
			explain = true;
		else
			files.emplace_back(argv[i], reloc, explain);
	}

	for (auto file : files) {
		file.bean.dump(verbose);
	}

	return EXIT_SUCCESS;
}
