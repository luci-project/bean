#include <dlh/stream/output.hpp>
#include <dlh/assert.hpp>
#include <dlh/string.hpp>

#include <bean/file.hpp>
#include <bean/helper/build_id.hpp>

struct Diff {
	BeanFile a_file, b_file;
	BuildID a_buildid, b_buildid;
	Bean::syminthash_t a_internal, b_internal;
	Bean::symhash_t a_extended, b_extended;
	bool include_dependencies;
	bool resolve_internal_relocations;
	Bean::ComparisonMode comparison_mode;

	Diff(const char * a_base, const char * a_path, const char * b_base, const char * b_path, bool dbgsym, bool reloc, bool dependencies, Bean::ComparisonMode comparison_mode) :
		a_file(a_path, dbgsym, reloc, false, a_base), b_file(b_path == nullptr ? a_path : b_path , dbgsym, reloc, false, b_base == nullptr ? a_base : b_base),
		a_buildid(a_file.binary.content), b_buildid(b_file.binary.content),
		a_internal(a_file.bean.diff_internal(b_file.bean, dependencies)), b_internal(b_file.bean.diff_internal(a_file.bean, dependencies)),
		a_extended(a_file.bean.diff_extended(b_file.bean, dependencies)), b_extended(b_file.bean.diff_extended(a_file.bean, dependencies)),
		include_dependencies(dependencies), resolve_internal_relocations(reloc), comparison_mode(comparison_mode) {
		assert(b_base != nullptr || b_path != nullptr);
	}

 private:
	template<typename T>
	static Pair<size_t, size_t> count(T & syms, bool (*filter)(const Bean::Symbol &)) {
		size_t num = 0;
		size_t bytes = 0;
		for (const auto & sym : syms)
			if (filter(sym)) {
				num++;
				bytes+=sym.size;
			}
		return { num, bytes };
	}

	static void print_startline(size_t depth) {
		cout << endl;
		for (size_t d = 0; d < depth; d++)
			cout << '\t';
	}

	static void print_count(const char * name, size_t depth, Pair<size_t, size_t> data) {
		print_startline(depth);
		cout << '"' << name << "\": {";
		print_startline(depth + 1);
		cout << "\"count\": " << data.first << ',';
		print_startline(depth + 1);
		cout << "\"size\": " << data.second;
		print_startline(depth);
		cout << '}';
	}

	void print_filter(const char * name, size_t depth, bool (*filter)(const Bean::Symbol &)) {
		print_startline(depth);
		cout << '"' << name << "\": {";
		print_count("total", depth + 1, count(b_file.bean, filter));
		cout << ',';
		print_startline(depth + 1);
		cout << "\"changed-internal\": {";
		print_count("added", depth + 2, count(b_internal, filter));
		cout << ',';
		print_count("removed", depth + 2, count(a_internal, filter));
		print_startline(depth + 1);
		cout << "},";
		print_startline(depth + 1);
		cout << "\"changed-extended\": {";
		print_count("added", depth + 2, count(b_extended, filter));
		cout << ',';
		print_count("removed", depth + 2, count(a_extended, filter));
		print_startline(depth + 1);
		cout << '}';
		print_startline(depth);
		cout << '}';
	}

 public:
	void print() {
		cout << '{';
		print_startline(1);
		cout << "\"patchable\": " << b_file.bean.patchable(a_file.bean, include_dependencies, comparison_mode) << ',';
		print_startline(1);
		cout << "\"settings\": {";
		print_startline(2);
		cout << "\"resolve_internal_relocations\": \"" << resolve_internal_relocations << "\",";
		print_startline(2);
		cout << "\"include_dependencies\": \"" << include_dependencies << "\",";
		print_startline(2);
		cout << "\"comparison_mode\": ";
		switch (comparison_mode) {
			case Bean::COMPARE_EXTENDED: cout << "\"COMPARE_EXTENDED\""; break;
			case Bean::COMPARE_WRITEABLE_INTERNAL: cout << "\"COMPARE_WRITEABLE_INTERNAL\""; break;
			case Bean::COMPARE_EXECUTABLE_EXTENDED: cout << "\"COMPARE_EXECUTABLE_EXTENDED\""; break;
			case Bean::COMPARE_ONLY_INTERNAL:  cout << "\"COMPARE_ONLY_INTERNAL\""; break;
			default: cout << "null";
		}
		print_startline(1);
		cout << "},";
		print_startline(1);
		cout << "\"build-id\": {";
		print_startline(2);
		cout << "\"added\": \"" << a_buildid.value << "\",";
		print_startline(2);
		cout << "\"removed\": \"" << b_buildid.value << '"';
		print_startline(1);
		cout << "},";
		print_filter("init", 1, [](const Bean::Symbol & sym) {
			return sym.section.has(Bean::Symbol::Section::SECTION_INIT);
		});
		cout << ',';
		print_filter("fini", 1, [](const Bean::Symbol & sym) {
			return sym.section.has(Bean::Symbol::Section::SECTION_FINI);
		});
		cout << ',';
		print_filter("text", 1, [](const Bean::Symbol & sym) {
			return sym.section.executable && sym.section.flags == Bean::Symbol::Section::SECTION_NONE;
		});
		cout << ',';
		print_filter("rodata", 1, [](const Bean::Symbol & sym) {
			return !sym.section.writeable && !sym.section.executable && sym.section.flags == Bean::Symbol::Section::SECTION_NONE;
		});
		cout << ',';
		print_filter("relro", 1, [](const Bean::Symbol & sym) {
			return sym.section.has(Bean::Symbol::Section::SECTION_RELRO);
		});
		cout << ',';
		print_filter("data", 1, [](const Bean::Symbol & sym) {
			return sym.section.writeable && sym.section.flags == Bean::Symbol::Section::SECTION_NONE && !Bean::TLS::is_tls(sym.address);
		});
		cout << ',';
		print_filter("bss", 1, [](const Bean::Symbol & sym) {
			return sym.section.writeable && sym.section.has(Bean::Symbol::Section::SECTION_NOBITS) && !Bean::TLS::is_tls(sym.address);
		});
		cout << ',';
		print_filter("tdata", 1, [](const Bean::Symbol & sym) {
			return sym.section.writeable && sym.section.flags == Bean::Symbol::Section::SECTION_NONE && Bean::TLS::is_tls(sym.address);
		});
		cout << ',';
		print_filter("tbss", 1, [](const Bean::Symbol & sym) {
			return sym.section.writeable && sym.section.has(Bean::Symbol::Section::SECTION_NOBITS) && Bean::TLS::is_tls(sym.address);
		});
		cout << endl << '}' << endl;
	}
};

int main(int argc, const char *argv[]) {
	Bean::ComparisonMode comparison_mode = Bean::COMPARE_EXTENDED;
	bool dependencies = false;
	bool dbgsym = false;
	bool reloc = false;
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
		} else if (String::compare(argv[i], "-i", 2) == 0) {
			for (size_t j = 1; argv[i][j] != '\0'; j++) {
				if (argv[i][j] == 'i') {
					comparison_mode = static_cast<Bean::ComparisonMode>(1 + static_cast<uint8_t>(comparison_mode));
				} else {
					cerr << "Unsupported parameter '" << argv[i] << endl;
					return EXIT_FAILURE;
				}
			}
		} else if (String::compare(argv[i], "-b") == 0) {
			if (old_base == nullptr) {
				old_base = argv[++i];
			} else if (new_base == nullptr) {
				new_base = argv[++i];
			} else {
				cerr << "Invalid third base parameter " << argv[++i] << endl;
				return EXIT_FAILURE;
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
		cerr << "Summary of differences between two ELF binaries A and B" << endl << endl
		     << "   Usage: " << argv[0] << " [-d] [-s] [-r] A B" << endl << endl
		     << "Parameters:" << endl
		     << "  -r    resolve (internal) relocations" << endl
		     << "  -d    include dependencies" << endl
		     << "  -s    use (external) debug symbols" << endl
		     << "  -i    do not check writeable section with external ID (only internal one) " << endl
		     << "  -ii   do only check executable sections with both IDs, use internal ID for everything else" << endl
		     << "  -iii  rely on internal ID only for comparison (and ignore external one)" << endl
		     << "  -b    base directory to search for debug files" << endl
		     << "        (if this is set a second time, it will be used for the second [new] binary)" << endl;
		return EXIT_FAILURE;
	}

	Diff(old_base, old_path, new_base, new_path, dbgsym, reloc, dependencies, comparison_mode).print();

	return EXIT_SUCCESS;
}
