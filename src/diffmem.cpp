#include <dlh/container/vector.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/parser/string.hpp>
#include <dlh/string.hpp>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	bool dependencies = false;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;
	size_t threshold = 0;

	if (!BeanFile::init())
		return EXIT_FAILURE;


	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0)
			dependencies = true;
		else if (a == nullptr)
			a = new BeanFile(argv[i]);
		else if (b == nullptr)
			b = new BeanFile(argv[i]);
		else if (threshold == 0 && Parser::string(threshold, argv[i]))
			continue;
		else
			cerr << "Ignoring argument " << argv[i] << endl;
	}

	if (b == nullptr) {
		delete a;
		cerr << "Usage: " << argv[0] << " [-d] OLD NEW [THRESHOLD]" << endl;
		return EXIT_FAILURE;
	}

	cout << "# " << a->path << " (" << a->size << " bytes) -> "
	             << b->path << " (" << b->size << " bytes)" << endl;
	for (const auto & mem : b->bean.diffmerge(a->bean, dependencies, threshold)) {
		cout << prefix << setw(16) << hex << mem.first
		     << ' ' << setw(6) << dec << mem.second
		     << " -> " << setw(16) << hex << (mem.first + mem.second) << endl;
	}

	delete a;
	delete b;
	return EXIT_SUCCESS;
}
