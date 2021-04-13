#include <iostream>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << "[-v] ELF-FILES" << std::endl;
		return EXIT_FAILURE;
	}

	bool verbose = false;
	std::vector<BeanFile> files;
	for (int i = 1; i < argc; i++) {
		if (std::string(argv[i]) == "-v")
			verbose = true;
		else
			files.emplace_back(argv[i]);
	}

	for (auto file : files) {
		file.bean.dump(verbose);
	}

	return EXIT_SUCCESS;
}
