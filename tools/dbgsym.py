#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import shutil
import argparse
import urllib.request
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, NoteSection

# TODO: Use pyelftools instead
class DebugSymbol:
	def __init__(self, file, root='', elf = None, debug_dirs = [ ], debuginfodcache = '.debug-cache'):
		self.root = Path(root).resolve() if root else Path('/')

		self.elf = elf
		if isinstance(file, io.BufferedReader):
			filepath = Path(file.name)
			if not self.elf:
				self.elf = ELFFile(file)
		else:
			filepath = Path(file)

		self.filepath = filepath.absolute().relative_to(self.root)

		if not debug_dirs:
			debug_dirs = [ 'usr/lib/debug' ]
		self.debug_dirs = debug_dirs
		self.debuginfodcache = debuginfodcache
		self.buildid = None
		self.debuglink = None


	def get_buildid(self):
		if not self.elf:
			self.elf = ELFFile(open(str(self.root / self.filepath), "rb"))

		if not self.buildid:
			for section in self.elf.iter_sections():
				if isinstance(section, NoteSection):
					for note in section.iter_notes():
						if note['n_type'] == 'NT_GNU_BUILD_ID' and note['n_size'] == 36:
							self.buildid = note['n_desc']
							return self.buildid

		return self.buildid


	def get_debuglink(self):
		if not self.elf:
			self.elf = ELFFile(open(str(self.root / self.filepath), "rb"))

		if not self.debuglink:
			for section in self.elf.iter_sections():
				if section.name == '.gnu_debuglink':
					self.debuglink = section.data().split(b'\x00', 1)[0].decode('ascii')
					return self.debuglink

		return self.debuglink


	def debug_symbol_paths(self, debuglink, buildid):
		# First try debug link
		if debuglink:
			yield (self.root / self.filepath.parent / debuglink)
			yield (self.root / self.filepath.parent / '.debug' / debuglink)
			for debug_dir in self.debug_dirs:
				yield (self.root / debug_dir / self.filepath.parent / debuglink)

		# Then Build ID
		if buildid:
			for debug_dir in self.debug_dirs:
				yield (self.root / debug_dir / '.build-id' / buildid[:2] / buildid[2:]).with_suffix('.debug')

		# continue with default search paths
		yield (self.root / self.filepath).with_suffix('.debug')
		yield (self.root / self.filepath.parent / '.debug' / self.filepath.name).with_suffix('.debug')
		for debug_dir in self.debug_dirs:
			yield (self.root / debug_dir / self.filepath).with_suffix('.debug')

		# and non conforming directories
		yield (self.root / self.filepath.parent / '.debug' / self.filepath.name)
		for debug_dir in self.debug_dirs:
			yield (self.root / debug_dir / self.filepath)

		# finally, check debuginfod cache
		if buildid and self.debuginfodcache:
			yield (Path('.') / self.debuginfodcache / '.build-id' / buildid[:2] / buildid[2:]).with_suffix('.debug')


	def find(self, debuglink = '', buildid = '', debuginfod = True):
		dbgsympaths = []

		if debuglink == '':
			debuglink = self.get_debuglink()

		if buildid == '':
			buildid = self.get_buildid()

		# Check all paths
		for dbgsym in self.debug_symbol_paths(debuglink, buildid):
			if dbgsym.exists():
				return str(dbgsym)

		# Try debuginfod
		if debuginfod and buildid and self.debuginfodcache:
			for service in [ 'https://debuginfod.debian.net', 'https://debuginfod.ubuntu.com', 'https://debuginfod.elfutils.org/' ]:
				try:
					with urllib.request.urlopen(f'{service}/buildid/{buildid}/debuginfo') as fp:
						target = (Path('.') / self.debuginfodcache / '.build-id' / buildid[:2] / buildid[2:]).with_suffix('.debug')
						target.parent.mkdir(parents=True, exist_ok=True)
						with open(target,'wb') as output:
							shutil.copyfileobj(fp, output)
						return str(target)
				except Exception as e:
					continue


if __name__ == '__main__':

	def dir_path(string):
		path = Path(string)
		if path.is_dir():
			return str(path.resolve())
		else:
			raise NotADirectoryError(string)

	# Arguments
	parser = argparse.ArgumentParser(prog='Search (external) debug symbols for ELF file')
	parser.add_argument('-d', '--debuginfod', action='store_true', help='Use Debuginfod service if no local symbols were found')
	parser.add_argument('-b', '--base', type=dir_path, help="Set base directory", default="/")
	parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
	parser.add_argument('files', type=argparse.FileType('rb'), help="ELF file(s)", nargs='+')

	args = parser.parse_args()

	for file in args.files:
		dbgsym = DebugSymbol(file, args.base)
		if args.verbose:
			print(f"\nELF {dbgsym.filepath}")

			if args.base:
				print(f"  - base: {dbgsym.root}")
			debuglink = dbgsym.get_debuglink()
			if debuglink:
				print(f"  - debug_link: {debuglink}")

			buildid = dbgsym.get_buildid()
			if buildid:
				print(f"  - buildid: {buildid}")

		dbgfile = dbgsym.find(debuginfod = args.debuginfod)
		if dbgfile:
			print(dbgfile)
		else:
			print("no debug file found")
