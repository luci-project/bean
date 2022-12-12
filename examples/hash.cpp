#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	// Check arguments
	if (argc < 2) {
		cerr << "Hash ELF binary" << endl << endl
		     << "   Usage: " << argv[0] << " [-r] [-s] [-b FOLDER] [-v[v[v]]] ELF-FILE[S]"<< endl << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -s    use (external) debug symbols" << endl
	         << "  -b    base directory to search for debug files" << endl
		     << "  -v    list address and names" << endl
		     << "  -vv   ... and dissassemble code" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		return EXIT_FAILURE;
	}

	Bean::Verbosity verbose = Bean::NONE;
	bool reloc = false;
	bool dbgsym = false;
	const char * base = nullptr;

	for (int i = 1; i < argc; i++) {
		if (String::compare(argv[i], "-r") == 0) {
			reloc = true;
		} else if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-b") == 0) {
			base = argv[++i];
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
			BeanFile file(argv[i], dbgsym, reloc, true, base);
			cout << "# " << file.binary.path << " (" << file.binary.size << " bytes):" << endl;
			file.bean.dump(cout, verbose);
			cout << endl;
		}
	}

	return EXIT_SUCCESS;
}
