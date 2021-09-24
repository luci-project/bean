#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>

int main(int argc, const char *argv[]) {
	Bean::Verbosity verbose = Bean::NONE;

	bool dependencies = false;
	bool dbgsym = false;
	bool reloc = false;
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

	if (new_path == nullptr) {
		cerr << "Usage: " << argv[0] << "[-d] [-s] [-r] [-v[v]] OLD NEW" << endl;
		return EXIT_FAILURE;
	}

	BeanFile old_file(old_path, dbgsym, reloc, verbose >= Bean::DEBUG);
	BeanFile new_file(new_path, dbgsym, reloc, verbose >= Bean::DEBUG);

	auto & diff = new_file.bean.diff(old_file.bean, dependencies);

	if (verbose == Bean::NONE)
		Bean::dump(cout, diff);
	else {
		auto removed = Bean::symtree_t(old_file.bean.diff(new_file.bean, dependencies));
		auto rnext = removed.begin();
		for (const auto & n : new_file.bean) {
			while (rnext != removed.end() && rnext->address <= n.address) {
				rnext->dump(cout, verbose, &old_file.bean.symbols, "\e[31m-");
				++rnext;
			}
			bool dbg = false;
			if (diff.contains(n)) {
				n.dump(cout, verbose, &new_file.bean.symbols, "\e[32m+");
			} else {
				n.dump(cout, Bean::VERBOSE, &new_file.bean.symbols, "\e[0m ");
			}
		}
		cout << "\e[0m";
	}

	return EXIT_SUCCESS;
}
