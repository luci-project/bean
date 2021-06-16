#include <dlh/stream/output.hpp>
#include <dlh/container/vector.hpp>
#include <dlh/string.hpp>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Usage: " << argv[0] << "[-r] [-v] [-x] ELF-FILES" << endl;
		return EXIT_FAILURE;
	}

	if (!BeanFile::init())
		return EXIT_FAILURE;

	bool verbose = false;
	bool reloc = false;
	bool explain = false;
	Vector<BeanFile> files;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0)
			reloc = true;
		else if (strcmp(argv[i], "-v") == 0)
			verbose = true;
		else if (strcmp(argv[i], "-x") == 0)
			explain = true;
		else
			files.emplace_back(argv[i], reloc, explain);
	}

	for (auto & file : files) {
		cout << "# " << file.path << " (" << file.size << " bytes):" << endl;
		file.bean.dump(verbose);
	}

	return EXIT_SUCCESS;
}
