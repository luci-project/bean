#include <dlh/stream/output.hpp>
#include <dlh/string.hpp>

#include "beanfile.hpp"

int main(int argc, const char *argv[]) {
	unsigned verbose = 0;
	bool dependencies = false;
	bool sections = false;
	BeanFile * a = nullptr;
	BeanFile * b = nullptr;

	if (!BeanFile::init())
		return EXIT_FAILURE;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v"))
			verbose = 1;
		else if (!strcmp(argv[i], "-vv"))
			verbose = 2;
		else if (!strcmp(argv[i], "-d"))
			dependencies = true;
		else if (!strcmp(argv[i], "-s"))
			sections = true;
		else if (a == nullptr)
			a = new BeanFile(argv[i]);
		else if (b == nullptr)
			b = new BeanFile(argv[i]);
		else
			cerr << "Ignoring argument " << argv[i] << endl;
	}

	if (b == nullptr) {
		delete a;
		cerr << "Usage: " << argv[0] << "[-v[v]] [-d] [-s] OLD NEW" << endl;
		return EXIT_FAILURE;
	}

	auto & diff = b->bean.diff(a->bean, dependencies);
	if (sections) {
		cout << "File " << b->path << endl;
		for (const auto & section : b->bean.elf.sections) {
			cout << "\e[1m"
			          << "[" << b->bean.elf.sections.index(section) << "] "
			          << section.name()
			          << "\e[0m";
			if (section.allocate()) {
				cout << " @ 0x" << hex << section.virt_addr()
				          << " (" << dec << section.size() << " Bytes)"
				          << " A";
			} else {
				cout << endl;
				continue;
			}
			if (section.writeable())
				cout << "W";
			if (section.executable())
				cout << "X";
			cout << ":" << endl;

			size_t i = 0, m = 0;
			const auto begin = b->bean.find(section.virt_addr());
			const auto end = b->bean.find(section.virt_addr() + section.size());
			for (auto it = begin; it != end; ++it) {
				cout << "\e[0m  ";
				if (diff.contains(*it)) {
					cout << "\e[33m";
					m++;
				}
				cout << flush;
				it->dump(verbose != 0);
				if (verbose == 2) {
					// refs
					bool header = false;
					for (const auto raddress : it->refs) {
						cout << (!header ? "      using " : "            ");
						header = true;
						auto rsym = b->bean.get(raddress);

						if (rsym == nullptr) {
							cout << "0x" << hex << raddress << dec << " [unresolved]";
						} else {
							cout << "0x" << hex << rsym->address << dec;
							if (raddress != rsym->address)
								cout << " + " << (raddress - rsym->address);
							if (rsym->name != nullptr)
								cout << " (" << rsym->name << ")";
						}
						cout << endl;
					}
					// deps
					header = false;
					for (const auto daddress : it->deps) {
						cout << (!header ? "    used by " : "            ");
						header = true;
						auto dsym = b->bean.get(daddress);

						if (dsym == nullptr) {
							cout << "0x" << hex << daddress << dec << " [unresolved]";
						} else {
							cout << "0x" << hex << dsym->address << dec;
							if (dsym->name != nullptr)
								cout << " (" << dsym->name << ")";
						}
						cout << endl;
					}
					cout << endl;
				}
				i++;
			}

			cout << "\e[0m(" << i << " symbols";
			if (m > 0)
				cout << ", \e[33m" << m << " modified\e[0m";
			cout << ")" << endl << endl;
		}
	} else {
		Bean::dump(diff, verbose != 0);
	}

	delete a;
	delete b;
	return EXIT_SUCCESS;
}
