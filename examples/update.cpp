#include <dlh/parser/string.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

TreeSet<const char *> ignore_writeable = { ".eh_frame_hdr", ".eh_frame", ".dynamic", ".data.rel.ro"};

int main(int argc, const char *argv[]) {
	Bean::Verbosity verbose = Bean::NONE;

	bool dependencies = false;
	bool reloc = false;
	bool merge = false;
	size_t threshold = 0;
	const char * old_path = nullptr;
	const char * new_path = nullptr;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;

	if (!BeanFile::init())
		return EXIT_FAILURE;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d")) {
			dependencies = true;
		} else if (strcmp(argv[i], "-r") == 0) {
			reloc = true;
		} else if (strncmp(argv[i], "-m", 2) == 0) {
			merge = true;
			if (!Parser::string(threshold, argv[i] + 2)) {
				cerr << "Unable to parse merge threshold!" << endl;
				return EXIT_FAILURE;
			}
		} else if (strncmp(argv[i], "-v", 2) == 0) {
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

	if (new_path == nullptr) {
		cerr << "Usage: " << argv[0] << "[-d] [-v[v[v]]] [-m[THRESHOLD]] OLD NEW" << endl;
		return EXIT_FAILURE;
	}

	BeanFile old_file(old_path, reloc, verbose >= Bean::DEBUG);
	BeanFile new_file(new_path, reloc, verbose >= Bean::DEBUG);

	auto & diff = new_file.bean.diff(old_file.bean, dependencies);

	cout << "# Changes at update of "
	     << old_file.path << " (" << old_file.size << " bytes) with "
	     << new_file.path << " (" << new_file.size << " bytes)" << endl;
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

	for (const auto & d : diff) {
		if (d.section.writeable && !ignore_writeable.contains(d.section.name)) {
			cerr << "# Writeable sections have changed - not updateable..." << endl;
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}
