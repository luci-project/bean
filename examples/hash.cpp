#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Usage: " << argv[0] << " [-r] [-v[v[v]]] ELF-FILES" << endl;
		return EXIT_FAILURE;
	}

	Bean::Verbosity verbose = Bean::NONE;
	bool reloc = false;
	bool explain = false;

	for (int i = 1; i < argc; i++) {
		if (String::compare(argv[i], "-r") == 0) {
			reloc = true;
		} else if (String::compare(argv[i], "-v", 2) == 0) {
			for (size_t j = 1; argv[i][j] != '\0'; j++) {
				if (argv[i][j] == 'v') {
					verbose = static_cast<Bean::Verbosity>(1 + static_cast<uint8_t>(verbose));
				} else {
					cerr << "Unsupported parameter '" << argv[i] << endl;
					return EXIT_FAILURE;
				}
			}
		} else if (argv[i][0] == '-') {
			cerr << "Unsupported parameter '" << argv[i] << endl;
			return EXIT_FAILURE;
		} else {
			BeanFile file(argv[i], reloc, verbose >= Bean::DEBUG);
			cout << "# " << file.path << " (" << file.size << " bytes):" << endl;
			file.bean.dump(cout, verbose);
			cout << endl;
		}
	}

	return EXIT_SUCCESS;
}
