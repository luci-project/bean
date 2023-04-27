// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <bean/helper/build_id.hpp>

#include <dlh/assert.hpp>
#include <dlh/string.hpp>
#include <dlh/stream/string.hpp>

BuildID::BuildID(const char * value) {
	if (value == nullptr)
		this->value[0] = '\0';
	else
		String::copy(this->value, value, count(this->value));
}

BuildID::BuildID(const Elf * file) {
	value[0] = '\0';
	if (file == nullptr || !file->header.valid())
		return;

	for (const auto & section : file->sections) {
		if (section.type() != Elf::SHT_NOTE)
			continue;
		for (const auto & note : section.get_notes()) {
			if (note.name() != nullptr && strcmp(note.name(), "GNU") == 0 && note.type() == Elf::NT_GNU_BUILD_ID) {
				BufferStream id(this->value, count(this->value));
				const uint8_t * desc = reinterpret_cast<const uint8_t *>(note.description());
				for (size_t i = 0; i < note.size(); i++)
					id << hex << right << setfill('0') << setw(2)  << static_cast<uint32_t>(desc[i]);
				id.flush();
				assert(this->value[count(this->value) - 1] == '\0');
				break;
			}
		}
	}
}
