#pragma once

#include <elfo/elf.hpp>
#include <dlh/systypes.hpp>
#include <dlh/stream/string.hpp>
#include <bean/helper/build_id.hpp>

class DebugSymbol {
	char elf_filepath[PATH_MAX + 1];

 public:
	const char * elf_dirname = nullptr;
	const char * elf_filename = nullptr;;
	char root[PATH_MAX + 1];
	StringStream<PATH_MAX + 1> debug_filepath;

	DebugSymbol(const char * elf_filepath, const char * root = nullptr);

	const char * find(const char * debug_link, const BuildID & build_id);

	inline const char * find(const BuildID & build_id) {
		return find(nullptr, build_id);
	}

	inline const char * find(const char * debug_link = nullptr) {
		BuildID no_build_id(0);
		return find(debug_link, no_build_id);
	}

	const char * find(const Elf & binary);
};
