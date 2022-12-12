#include <dlh/parser/string.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	Bean::Verbosity verbose = Bean::NONE;

	bool dependencies = false;
	bool dbgsym = false;
	bool reloc = false;
	bool merge = false;
	size_t threshold = 0;
	const char * old_base = nullptr;
	const char * new_base = nullptr;
	const char * old_path = nullptr;
	const char * new_path = nullptr;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;

	for (int i = 1; i < argc; i++) {
		if (!String::compare(argv[i], "-d")) {
			dependencies = true;
		} else if (String::compare(argv[i], "-s") == 0) {
			dbgsym = true;
		} else if (String::compare(argv[i], "-r") == 0) {
			reloc = true;
		} else if (String::compare(argv[i], "-b") == 0) {
			if (old_base == nullptr) {
				old_base = argv[++i];
			} else if (new_base == nullptr) {
				new_base = argv[++i];
			} else {
				cerr << "Invalid third base parameter " << argv[++i] << endl;
				return EXIT_FAILURE;
			}
		} else if (String::compare(argv[i], "-m", 2) == 0) {
			merge = true;
			if (!Parser::string(threshold, argv[i] + 2)) {
				cerr << "Unable to parse merge threshold!" << endl;
				return EXIT_FAILURE;
			}
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
		} else if (old_path == nullptr) {
			old_path = argv[i];
		} else if (new_path == nullptr) {
			new_path = argv[i];
		} else {
			cerr << "Ignoring argument " << argv[i] << endl;
		}
	}

	if (new_path == nullptr && new_base == nullptr) {
		cerr << "Check if NEW ELF binary can update OLD" << endl << endl
		     << "   Usage: " << argv[0] << " [-r] [-d] [-s] [-m[THRESHOLD]] [-b [OLD]BASE [-b NEWBASE]] [-v[v[v]]] OLD NEW" << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -d    include dependencies" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "        (if this is set a second time, it will be used for the second [new] binary)" << endl
		     << "  -m    merge memory areas" << endl
		     << "  -mSZ  ... while ignoring gaps up to a threshold of SZ bytes" << endl
		     << "  -v    list address and names" << endl
		     << "  -vv   ... and dissassemble code" << endl
		     << "  -vvv  ... and show all references and relocations" << endl;
		return EXIT_FAILURE;
	}

	BeanFile old_file(old_path, dbgsym, reloc, verbose >= Bean::DEBUG, old_base);
	BeanFile new_file(new_path == nullptr ? old_path : new_path, dbgsym, reloc, verbose >= Bean::DEBUG, new_base == nullptr ? old_base : new_base);

	auto & diff = new_file.bean.diff(old_file.bean, dependencies);

	cout << "# Changes at update of "
	     << old_file.binary.path << " (" << old_file.binary.size << " bytes) with "
	     << new_file.binary.path << " (" << new_file.binary.size << " bytes)" << endl;
	Bean::dump(cout, diff, verbose);
	cout << endl;

	if (merge) {
		cout << "# Required memory segments";
		if (threshold != 0)
			cout << " (ignoring gaps up to " << threshold << " bytes)";
		cout << " from " << new_path << ':' << endl;

		for (const auto & mem : new_file.bean.merge(diff, threshold)) {
			cout << "#   " << prefix << setfill('0') << setw(16) << hex << mem.address
			     << " - " << setw(16) << hex << (mem.address + mem.size)
			     << " R" << (mem.writeable ? 'W' : ' ') << (mem.executable ? 'X' : ' ')
			     << " (" << setfill(' ') << dec << mem.size << " bytes)" << endl;
		}
	}

	if (Bean::patchable(diff)) {
		return EXIT_SUCCESS;
	} else {
		cerr << "# Writeable sections have changed - not updateable..." << endl;
		return EXIT_FAILURE;
	}
}
