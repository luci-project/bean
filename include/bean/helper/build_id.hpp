#pragma once

#include <elfo/elf.hpp>

struct BuildID {
	// null terminated hex representation of build id
	char value[41];

	BuildID(const char * value = nullptr);

	BuildID(const BuildID & other) : BuildID(other.value) {}

	BuildID(const Elf * file);

	BuildID(const Elf & file) : BuildID(&file) {}

	bool available() const {
		return value[0] != '\0';
	}

	operator bool() const {
		return available();
	}
};
