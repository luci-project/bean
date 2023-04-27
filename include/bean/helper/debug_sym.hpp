// Binary Explorer & Analyzer (Bean)
// Copyright 2021-2023 by Bernhard Heinloth <heinloth@cs.fau.de>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <elfo/elf.hpp>
#include <dlh/systypes.hpp>
#include <dlh/stream/string.hpp>
#include <bean/helper/build_id.hpp>

class DebugSymbol {
	char elf_filepath[PATH_MAX + 1];

 public:
	const char * elf_dirname = nullptr;
	const char * elf_filename = nullptr;
	char root[PATH_MAX + 1];
	StringStream<PATH_MAX + 1> debug_filepath;

	/*! \brief Construct new debug symbol finder
	 *  \param elf_filepath path to binary (required for debug symbols in same directory)
	 *  \param root use alternative root (or `nullptr` for real root)
	 */
	explicit DebugSymbol(const char * elf_filepath, const char * root = nullptr);

	/*! \brief Find external debug file
	 *  \param debug_link path to debug symbol file (or `nullptr` if not available)
	 *  \param build_id BuildID of Elf
	 *  \return path to debug file
	 */
	const char * find(const char * debug_link, const BuildID & build_id);

	/*! \brief Find external debug file
	 *  \param build_id BuildID of Elf
	 *  \return path to debug file
	 */
	inline const char * find(const BuildID & build_id) {
		return find(nullptr, build_id);
	}

	/*! \brief Find external debug file
	 *  \param debug_link path to debug symbol file (or `nullptr` if not available)
	 *  \return path to debug file
	 */
	inline const char * find(const char * debug_link = nullptr) {
		BuildID no_build_id{};
		return find(debug_link, no_build_id);
	}

	/*! \brief Find external debug file
	 *  \param binary Elf to be parsed for debug link / symbols and BuildID
	 *  \return path to debug file
	 */
	const char * find(const Elf & binary);


	/*! \brief get path linked external debug file
	 *  \param binary Elf to be parsed for debug link
	 *  \return debug link path to debug symbols if available
	 */
	static const char * link(const Elf & binary);
};
