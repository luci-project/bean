#include <bean/helper/debug_sym.hpp>

#include <dlh/stream/buffer.hpp>
#include <dlh/stream/output.hpp>
#include <dlh/syscall.hpp>
#include <dlh/assert.hpp>
#include <dlh/string.hpp>
#include <dlh/file.hpp>


DebugSymbol::DebugSymbol(const char * elf_filepath, const char * root){
	// Root
	if (root == nullptr || root[0] == '\0' || (root[0] == '/' && root[1] == '\0')) {
		this->root[0] = '\0';
	} else {
		if (!File::absolute(root, this->root, PATH_MAX + 1))
			String::copy(this->root, root, PATH_MAX);

		struct stat sb;
		auto stat = Syscall::stat(this->root, &sb);
		if (stat.success() && S_ISDIR(sb.st_mode)) {
			this->root[PATH_MAX] = '\0';
			for (size_t i = String::len(this->root); i > 0 && this->root[i - 1] == '/'; i--)
				this->root[i - 1] = '\0';
		}
		else {
			this->root[0] = '\0';
		}
	}

	// Elf file
	if (elf_filepath == nullptr || elf_filepath[0] == '\0') {
		this->elf_filepath[0] = '\0';
	} else {
		if (!File::absolute(elf_filepath, this->elf_filepath, PATH_MAX + 1))
			BufferStream(this->elf_filepath, PATH_MAX + 1) << this->root << "/" << elf_filepath;
		if (File::exists(this->elf_filepath)) {
			this->elf_filepath[PATH_MAX] = '\0';
			File::pathsplit(this->elf_filepath).assign(this->elf_dirname, this->elf_filename);
			size_t root_len = String::len(this->root);
			if (String::compare(this->root, this->elf_dirname, root_len) == 0)
				this->elf_dirname += root_len;
			while(this->elf_dirname[0] == '/')
				this->elf_dirname++;

		} else {
			this->elf_filepath[0] = '\0';
		}
	}
}

static const char * const debug_dirs[] = { "usr/lib/debug" };

const char * DebugSymbol::find(const char * debug_link, const BuildID & build_id) {
	if (elf_dirname == nullptr || elf_filename == nullptr)
		return nullptr;

	// first try debug link
	if (debug_link != nullptr) {
		debug_filepath << root << '/' << elf_dirname << '/' << debug_link;
		if (File::exists(debug_filepath.str()))
			return debug_filepath.str();
		else
			debug_filepath.clear();

		debug_filepath << root << '/' << elf_dirname << "/.debug/" << debug_link;
		if (File::exists(debug_filepath.str()))
			return debug_filepath.str();
		else
			debug_filepath.clear();

		for (auto & debug_dir : debug_dirs) {
			debug_filepath << root << '/' << debug_dir << '/' << elf_dirname << debug_link;
			if (File::exists(debug_filepath.str()))
				return debug_filepath.str();
			else
				debug_filepath.clear();
		}
	}

	// then Build ID
	if (build_id.available()) {
		for (auto & debug_dir : debug_dirs) {
			debug_filepath << root << '/' << debug_dir << "/.build-id/" << build_id.value[0] << build_id.value[1] << '/' << (build_id.value + 2) << ".debug";
			if (File::exists(debug_filepath.str()))
				return debug_filepath.str();
			else
				debug_filepath.clear();
		}
	}

	// continue with default search paths
	debug_filepath << root << '/' << elf_dirname << '/' << elf_filename << ".debug";
	if (File::exists(debug_filepath.str()))
		return debug_filepath.str();
	else
		debug_filepath.clear();

	debug_filepath << root << '/' << elf_dirname << "/.debug/" << elf_filename << ".debug";
	if (File::exists(debug_filepath.str()))
		return debug_filepath.str();
	else
		debug_filepath.clear();

	for (auto & debug_dir : debug_dirs) {
		debug_filepath << root << '/' << debug_dir << '/' << elf_dirname << '/' << elf_filename << ".debug";
		if (File::exists(debug_filepath.str()))
			return debug_filepath.str();
		else
			debug_filepath.clear();
	}

	// and non conforming directories
	debug_filepath << root << '/' << elf_dirname << "/.debug/" << elf_filename;
	if (File::exists(debug_filepath.str()))
		return debug_filepath.str();
	else
		debug_filepath.clear();

	for (auto & debug_dir : debug_dirs) {
		debug_filepath << root << '/' << debug_dir << '/' << elf_dirname << '/' << elf_filename;
		if (File::exists(debug_filepath.str()))
			return debug_filepath.str();
		else
			debug_filepath.clear();
	}

	// Nothing found
	return nullptr;
}

const char * DebugSymbol::find(const Elf & binary) {
	if (!binary.header.valid() || binary.header.type() == Elf::ET_CORE)
		return nullptr;

	const char * debug_link = nullptr;
	for (auto & section: binary.sections)
		if (String::compare(section.name(), ".gnu_debuglink") == 0) {
			debug_link = reinterpret_cast<const char *>(section.data());
		} else if (String::compare(section.name(), ".debug_", 7) == 0) {
			debug_filepath << debug_filepath << root << '/' << elf_dirname << '/' << elf_filename;
			if (File::exists(debug_filepath.str()))
				return debug_filepath.str();
			else
				debug_filepath.clear();
		}

	BuildID build_id(binary);

	return find(debug_link, build_id);
}

const char * DebugSymbol::link(const Elf & binary) {
	for (auto & section: binary.sections)
		if (String::compare(section.name(), ".gnu_debuglink") == 0)
			return reinterpret_cast<const char *>(section.data());
	return nullptr;
}