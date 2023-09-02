// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <bean/bean.hpp>

#include <dlh/is_in.hpp>


struct BeanUpdate {
	enum Flags : uint32_t {
		FLAG_NONE                = 0,
		FLAG_USE_SYMBOL_NAMES    = 1 << 0,
		FLAG_ONLY_EXECUTABLE     = 1 << 1,
		FLAG_ONLY_BRANCH_RELS    = 1 << 2,
		FLAG_INCLUDE_TRAMPOLINES = 1 << 3,
		FLAG_IGNORE_LOCAL_RELS   = 1 << 4,
	};
	uint32_t flags = FLAG_NONE;

	explicit BeanUpdate(uint32_t flags = FLAG_NONE) : flags(flags) {}

	template<typename DATA = void, bool (*REDIRECT)(uintptr_t from, uintptr_t to, size_t size, DATA * custom_data) = nullptr, bool (*RELOCATE)(const Bean::SymbolRelocation & rel, uintptr_t to, const Bean::Symbol & target, DATA * custom_data) = nullptr, void (*SKIPMSG)(uintptr_t from, uintptr_t to, const char * reason, DATA * custom_data) = nullptr>
	void process(const Bean & from, const Bean & to, uintptr_t from_base = 0, uintptr_t to_base = 0, DATA * custom_data = nullptr) const {
		const auto & map = from.map(to, (flags & FLAG_USE_SYMBOL_NAMES) != 0);

		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Waddress"

		for (const auto & from_sym : from.symbols) {
			bool is_func = from_sym.section.executable && is(from_sym.type).in(Bean::Symbol::TYPE_UNKNOWN, Bean::Symbol::TYPE_FUNC, Bean::Symbol::TYPE_INDIRECT_FUNC);

			// Skip trampoline functions
			if (is_func && (flags & FLAG_INCLUDE_TRAMPOLINES) == 0 && (from_sym.flags & Bean::Symbol::SYMBOL_TRAMPOLINE) != 0)
				continue;

			// Find matching symbol
			bool same_internal_id = false;
			if (const auto & new_target = map.find(from_sym.address)) {
				if (const auto & new_target_sym = to.symbols.floor(new_target->value)) {
					same_internal_id = from_sym.id.internal == new_target_sym->id.internal;
					// Full redirect (skip trampolines)
					if (is_func && (from_sym.flags & Bean::Symbol::SYMBOL_TRAMPOLINE) == 0) {
						size_t offset = 0;
						// endbr instruction is 4 bytes
						if ((from_sym.flags & Bean::Symbol::SYMBOL_USING_CET) != 0)
							offset += 4;
						assert(offset < from_sym.size);

						// Remaining size until end of symbol
						auto size = from_sym.size - offset;
						// Limit size to start of first relocated instruction
						// (to prevent issues during re-relocation with static redirects)
						if (const auto & rel = from_sym.rels.lowest()) {
							auto rel_start = rel->offset - rel->instruction_offset - from_sym.address;
							if (rel_start <= offset)
								size = 0;
							else
								size = rel_start - offset;
						}
						if (REDIRECT != nullptr)
							REDIRECT(from_sym.address + offset + from_base, new_target_sym->address + to_base, size, custom_data);
					}
				}
			}

			// Check all relocations
			if (from_sym.rels.empty())
				continue;
			for (const auto rel : from_sym.rels) {
				// for each relocation target check if there is a new one
				if (const auto new_target = map.find(rel.target)) {
					// The symbol to which the target maps
					const auto & new_target_sym = to.symbols.floor(new_target->value);
					assert(new_target_sym);
					if ((flags & FLAG_ONLY_EXECUTABLE) != 0 && !new_target_sym->section.executable)
						continue;

					// check relocation information
					bool is_branch = (rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_BRANCH) != 0;
					if ((flags & FLAG_ONLY_BRANCH_RELS) != 0 && !is_branch)
						continue;
					bool is_local = (rel.instruction_access & Bean::SymbolRelocation::ACCESSFLAG_LOCAL) != 0;

					bool insert_redirect = false;
					if (is_func && is_branch && is_local && (flags & FLAG_IGNORE_LOCAL_RELS) == 0) {
						// If the target offset id is identical, the control flow can be redirected
						const auto old_target_offset_id = from_sym.offset_ids.find(rel.target - from_sym.address);
						const auto new_target_offset_id = new_target_sym->offset_ids.find(new_target->value - new_target_sym->address);
						if (old_target_offset_id && new_target_offset_id && old_target_offset_id->value == new_target_offset_id->value)
							insert_redirect = true;
						else if (SKIPMSG != nullptr)
							SKIPMSG(rel.offset - rel.instruction_offset + from_base, new_target->value + to_base, "different offset ID", custom_data);
					} else if (same_internal_id) {
						if (RELOCATE != nullptr)
							insert_redirect = !RELOCATE(rel, new_target->value + to_base, *new_target_sym, custom_data);
					} else if (SKIPMSG != nullptr) {
						SKIPMSG(rel.offset + from_base, new_target->value + to_base, "different internal ID", custom_data);
					}
					if (insert_redirect && REDIRECT != nullptr)
						REDIRECT(rel.offset - rel.instruction_offset + from_base, new_target->value + to_base, 0, custom_data);
				} else if (SKIPMSG != nullptr) {
					SKIPMSG(rel.offset + from_base, 0, "no target found", custom_data);
				}
			}
		}
	}

	#pragma GCC diagnostic push
};
