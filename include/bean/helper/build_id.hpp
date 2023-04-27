// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <elfo/elf.hpp>

struct BuildID {
	// null terminated hex representation of build id
	char value[41];

	explicit BuildID(const char * value = nullptr);

	explicit BuildID(const Elf * file);

	explicit BuildID(const Elf & file) : BuildID(&file) {}

	BuildID(const BuildID & other) : BuildID(other.value) {}

	bool available() const {
		return value[0] != '\0';
	}

	operator bool() const {
		return available();
	}
};
