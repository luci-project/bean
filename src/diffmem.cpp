#include <algorithm>
#include <iterator>
#include <cstdio>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	bool dependencies = false;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;
	size_t threshold = 0;
	for (int i = 1; i < argc; i++) {
		const std::string arg(argv[i]);
		if (arg == "-d")
			dependencies = true;
		else if (a == nullptr)
			a = new BeanFile(argv[i]);
		else if (b == nullptr)
			b = new BeanFile(argv[i]);
		else if (threshold == 0)
			threshold = atol(argv[i]);
		else
			printf("Ignoring argument %s\n", argv[i]);
	}

	if (b == nullptr) {
		delete a;
		printf("Usage: %s [-d] OLD NEW [THRESHOLD]\n", argv[0]);
		return EXIT_FAILURE;
	}

	for (const auto & mem : b->bean.diffmerge(a->bean, dependencies, threshold)) {
		printf("0x%016lx %6lu -> 0x%016lx\n", mem.first, mem.second, mem.first + mem.second);
	}

	delete a;
	delete b;
	return EXIT_SUCCESS;
}
