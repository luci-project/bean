// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "capstone.hpp"

#include <dlh/mem.hpp>
#include <dlh/string.hpp>
#include <dlh/stream/buffer.hpp>

static int capstone_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
	return static_cast<int>(BufferStream(str, size).format(format, ap));
}

static void * capstone_calloc(size_t nmemb, size_t size) {
	return reinterpret_cast<void*>(Memory::alloc_array(nmemb, size));
}

bool capstone_init() {
	static bool initialized = false;
	if (!initialized) {
		// Capstone (used by Bean) without libc
		cs_opt_mem setup = {
			.malloc = Memory::alloc,
			.calloc = capstone_calloc,
			.realloc = Memory::realloc,
			.free = Memory::free,
			.vsnprintf = capstone_vsnprintf
		};

		initialized = ::cs_option(0, CS_OPT_MEM, reinterpret_cast<size_t>(&setup)) == 0;
	}
	return initialized;
}

// Symbols required by capstone...
extern "C" int strcmp(const char *s1, const char *s2) {
	return String::compare(s1, s2);
}

extern "C" int strncmp(const char *s1, const char *s2, size_t n) {
	return String::compare(s1, s2, n);
}

extern "C" size_t strlen(const char *s) {
	return String::len(s);
}

extern "C" char * strcpy(char *dest, const char *src) { //NOLINT
	return String::copy(dest, src);
}

extern "C" char * strncpy(char *dest, const char *src, size_t n) {
	return String::copy(dest, src, n);
}

extern "C" void* memcpy(void * __restrict__ dest, void const * __restrict__ src, size_t size) {
	return Memory::copy(dest, src, size);
}

extern "C" void* memmove(void * dest, void const * src, size_t size) {
	return Memory::move(dest, src, size);
}

extern "C" void* memset(void * dest, int c, size_t size) {
	return Memory::set(dest, c, size);
}

bool capstone_dump(BufferStream & out, void * ptr, size_t size, uintptr_t start) {
	capstone_init();
	csh cshandle;
	bool r = false;
	if (::cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) == CS_ERR_OK) {
		cs_insn *insn = cs_malloc(cshandle);
		if (insn != nullptr) {
			const uint8_t * data = reinterpret_cast<const uint8_t *>(ptr);
			while (cs_disasm_iter(cshandle, &data, &size, &start, insn)) {
				// Address
				out.format("0x%06llx: ", insn->address);
				// Machine Bytes
				for (size_t i = 0; i < 15; i++) {
					if (i < insn->size)
						out.format("%02x ", static_cast<unsigned>(insn->bytes[i]));
					else
						out.format("   ");
				}
				// Mnemonix + opstring
				out.format("%s %s\n", insn->mnemonic, insn->op_str);
			}
			r = true;
			cs_free(insn, 1);
		}
		cs_close(&cshandle);
	}
	return r;
}
