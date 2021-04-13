#include <iostream>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " ELF-FILES" << std::endl;
		return EXIT_FAILURE;
	}

	std::vector<BeanFile> files;
	for (int i = 1; i < argc; i++) {
		files.emplace_back(argv[i]);
	}

	for (auto file : files) {
		file.bean.dump(true);
	}

	return EXIT_SUCCESS;
}
