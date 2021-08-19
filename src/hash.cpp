#include <dlh/stream/output.hpp>
#include <dlh/container/vector.hpp>
#include <dlh/string.hpp>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Usage: " << argv[0] << "[-r] [-v [-v [-v]]] ELF-FILES" << endl;
		return EXIT_FAILURE;
	}

	if (!BeanFile::init())
		return EXIT_FAILURE;

	Bean::Verbosity verbose = Bean::NONE;
	bool reloc = false;
	bool explain = false;
	Vector<BeanFile> files;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0)
			reloc = true;
		else if (strcmp(argv[i], "-v") == 0)
			verbose = static_cast<Bean::Verbosity>(1 + static_cast<uint8_t>(verbose));
		else
			files.emplace_back(argv[i], reloc, verbose >= Bean::DEBUG);
	}

	for (auto & file : files) {
		cout << "# " << file.path << " (" << file.size << " bytes):" << endl;
		file.bean.dump(verbose);
	}

	return EXIT_SUCCESS;
}
