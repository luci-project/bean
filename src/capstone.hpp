// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <capstone/capstone.h>
#include <dlh/stream/buffer.hpp>

bool capstone_init();

bool capstone_dump(BufferStream & out, void * ptr, size_t size, uintptr_t start);

inline bool capstone_dump(BufferStream & out, void * ptr, size_t size)  {
	return capstone_dump(out, ptr, size, reinterpret_cast<uintptr_t>(ptr));
}
