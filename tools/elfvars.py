#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import io
import sys
import json
import errno
import types
import shelve
import socket
import xxhash
import os.path
import argparse
import functools
import selectors
import traceback
import pprint

from pathlib import Path
from dwarfvars import DwarfVars
from dbgsym import DebugSymbol

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, NoteSection
from elftools.elf.constants import P_FLAGS

PAGE_SIZE = 4096

def strcmp(a, b):
	if a < b:
		return -1
	elif a > b:
		return 1
	else:
		return 0

def page_start(adr):
	return adr - (adr % PAGE_SIZE)

def compare_symbols(a, b):
	if a['category'] != b['category']:
		return strcmp(a['category'], b['category'])
	elif a['value'] == b['value']:
		return strcmp(a['name'], b['name'])
	else:
		return a['value'] - b['value']

def sortuniq_symbols(symlist):
	l = None
	for s in sorted(symlist, key=functools.cmp_to_key(compare_symbols)):
		if l and l['value'] == s['value'] and l['name'] == s['name']:
			if l['size'] != s['size']:
				print(f"Size mismatch for duplicate {l['name']}: {l['size']} vs {s['size']}", file=sys.stderr)
		else:
			l = s
			yield s

def sortuniq_datatypes(datatypelist):
	l = None
	for s in sorted(datatypelist, key= lambda x: x['type']):
		if l and l['type'] == s['type']:
			if l['size'] != s['size']:
				print(f"Size mismatch for duplicate {l['type']}: {l['size']} vs {s['size']}", file=sys.stderr)
			elif l['hash'] != s['hash']:
				print(f"Hash mismatch for duplicate {l['type']}: {l['hash']} vs {s['hash']}", file=sys.stderr)
		else:
			l = s
			yield s

class ElfVar:
	def __init__(self, file, root=''):
		# Find ELF file
		self.root = Path(root).absolute()
		if isinstance(file, io.BufferedReader):
			self.path = Path(file.name).resolve()
			self.file = file
		else:
			path = Path(file)
			if path.exists():
				self.path = path.absolute()
			elif (self.root / path).exists():
				self.path = (self.root / path)
			else:
				raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), file)
			self.file = open(str(self.path), "rb")

		self.elf = ELFFile(self.file)
		self.dbgsym = None

		# Parse segments
		self.segments = []
		self.categories = set()
		self.sec2seg = {}
		self.relro = None
		self.dwarf = None

		# Get build ID, debug link and comment (if available)
		self.buildid = None
		self.debuglink = None
		self.comment = None
		for section in self.elf.iter_sections():
			if section.name == '.gnu_debuglink':
				self.debuglink = section.data().split(b'\x00', 1)[0].decode('ascii')
			elif section.name == '.comment':
				self.comment = section.data().split(b'\x00', 1)[0].decode('ascii')
			elif isinstance(section, NoteSection):
				for note in section.iter_notes():
					if note['n_type'] == 'NT_GNU_BUILD_ID' and note['n_size'] == 36:
						self.buildid = note['n_desc']
						break

	def load_debug_symbols(self, extern = True, aliases = True, names = True):
		if self.elf.has_dwarf_info() and next(self.elf.get_dwarf_info().iter_CUs(), False):
			self.dbgsym = self.path
		elif extern:
			self.dbgsym = DebugSymbol(self.path, self.root).find(self.debuglink, self.buildid)
		if self.dbgsym:
			if not self.comment:
				with  open(self.dbgsym, "rb") as dbgelf:
					for section in ELFFile(dbgelf).iter_sections():
						if section.name == '.comment':
							self.comment = section.data().split(b'\x00', 1)[0].decode('ascii')
			self.dwarf = DwarfVars(self.dbgsym, aliases = aliases, names = names)

	def load_segments(self):
		if len(self.segments) == 0:
			for segment in self.elf.iter_segments():
				if segment['p_type'] in [ 'PT_LOAD', 'PT_TLS', 'PT_GNU_RELRO' ]:
					cat = ''
					if segment['p_flags'] & P_FLAGS.PF_R != 0:
						cat += 'R'
					if segment['p_flags'] & P_FLAGS.PF_W != 0:
						cat += 'W'
					if segment['p_flags'] & P_FLAGS.PF_X != 0:
						cat += 'X'
					if segment['p_type'] == 'PT_TLS':
						cat = 'TLS'
					self.categories.add(cat)

					data = {
						'category': cat,
						'value': segment['p_vaddr'],
						'size': segment['p_memsz']
					}

					if segment['p_type'] == 'PT_GNU_RELRO':
						self.relro = data
					else:
						self.segments.append(data)
						segidx = len(self.segments) - 1

						for s in range(self.elf.num_sections()):
							if segment.section_in_segment(self.elf.get_section(s)):
								self.sec2seg[s] = segidx

	def symbols(self):
		symbols = []
		for section in self.elf.iter_sections():
			if isinstance(section, SymbolTableSection):
				for sym in section.iter_symbols():
					if sym['st_shndx'] != 'SHN_UNDEF' and sym['st_info']['type'] in [ 'STT_OBJECT', 'STT_COMMON', 'STT_TLS' ] and sym['st_size'] > 0:
						segment = self.segments[self.sec2seg[sym['st_shndx']]]
						if self.relro and 'W' in segment['category'] and sym['st_value'] >= self.relro['value'] and sym['st_value'] + sym['st_size'] < self.relro['value'] + self.relro['size']:
							segment = self.relro
						#assert(sym['st_value'] - segment['value'] + sym['st_size'] <= segment['size'])
						value = sym['st_value']
						align = sym['st_value']
						if sym['st_info']['type'] == 'STT_TLS':
							tls = True
						else:
							tls = False
							value -= page_start(segment['value'])
							align %= PAGE_SIZE

						symbols.append({
							'name': sym.name,
							'value': value,
							'size': sym['st_size'] if isinstance(sym['st_size'], int) else int(sym['st_size'],0),
							'align': align,
							'category': 'TLS' if tls else segment['category'],
							'external': True if sym['st_info']['bind'] == 'STB_GLOBAL' else False
						})
		return symbols

	def symbols_debug(self):
		# Prepare format of dwarf variables
		dwarfsyms = self.dwarf.get_vars(tls = False)
		for dvar in dwarfsyms:
			for seg in self.segments:
				if dvar['value'] >= seg['value'] and dvar['value'] + dvar['size'] <= seg['value'] + seg['size']:
					if self.relro and 'W' in seg['category'] and dvar['value'] >= self.relro['value'] and dvar['value'] + dvar['size'] < self.relro['value'] + self.relro['size']:
						seg = self.relro
					dvar['align'] = dvar['value'] % PAGE_SIZE
					dvar['value'] = dvar['value'] - page_start(seg['value'])
					dvar['category'] = seg['category']
					break
			else:
				raise RuntimeError("No segment found for address {}".format(hex(dvar['value'])))

		for dvar in self.dwarf.get_vars(tls = True):
			dvar['align'] = dvar['value'] % PAGE_SIZE;
			dvar['category'] = 'TLS'
			dwarfsyms.append(dvar)

		return dwarfsyms


	def functions(self):
		names = []
		for section in self.elf.iter_sections():
			if isinstance(section, SymbolTableSection):
				for sym in section.iter_symbols():
					if sym['st_shndx'] != 'SHN_UNDEF' and sym['st_info']['type'] in [ 'STT_FUNC' ] and sym['st_size'] > 0 and sym['st_info']['bind'] == 'STB_GLOBAL' and sym['st_value'] != 0:
						names.append((sym.name.split('@')[0], sym['st_value']))
		return sorted(set(names))


	def functions_debug(self, filter = []):
		decls = {}
		for name, addr, ret, params, hash in self.dwarf.iter_func(only_external = True):
			if len(filter) > 0:
				for f in filter:
					if name == f[0] or addr == f[1]:
						decls[name] = f"{ret} {f[0]}({params})"
						break
			else:
				decls[name] = f"{ret} {name}({params})"

		return [ decls[k] for k in sorted(decls) ]


	def summary(self, datatypes = True, functions_decl = True, writable_only = False, systypes = False, names = True, verbose = False):
		symbols = self.symbols()
		variables = []
		if self.dbgsym and self.dwarf:
			si = sortuniq_symbols(symbols)
			di = sortuniq_symbols(self.symbols_debug())

			s = next(si, None)
			d = next(di, None)
			while s or d:
				if not s:
					variables.append(d)
					d = next(di, None)
				elif not d:
					variables.append(s)
					s = next(si, None)
				elif d['value'] == s['value'] and s['name'].startswith(d['name']):
					if d['size'] != s['size']:
						raise RuntimeError(f"Size mismatch for {s['name']}: {d['size']} vs {s['size']}")
					if d['category'] != s['category']:
						raise RuntimeError(f"category mismatch for {s['name']}: {d['category']} vs {s['category']}")
#					if d['external'] != s['external']:
#						raise RuntimeError(f"External mismatch for {s['name']}")
					v = s
					for key in [ 'type', 'hash', 'source' ]:
						v[key] = d[key]
					variables.append(v)
					s = next(si, None)
					d = next(di, None)
				else:
					c = compare_symbols(d, s)
					assert(c != 0)
					if c < 0:
						variables.append(d)
						d = next(di, None)
					else:
						if not s['external']:
							RuntimeError(f"No DWARF def of {s['name']} found")
						variables.append(s)
						s = next(si, None)
		else:
			variables = list(sortuniq_symbols(symbols))

		info = {
			"file": str(self.path.relative_to(self.root)),
			"buildid": self.buildid,
			"variables": len(variables)
		}
		if self.dbgsym and self.dwarf:
			info["debug"] = str(Path(self.dbgsym).relative_to(self.root)) if self.root else self.dbgsym
			info["debug-incomplete"] = self.dwarf and self.dwarf.incomplete
		if self.comment:
			info["comment"] = self.comment

		for cat in sorted(self.categories):
			if writable_only and not 'W' in cat and cat != 'TLS':
				continue

			info[cat] = {}
			if verbose:
				info[cat]["details"] = []
			vars = filter(lambda x: x['category'] == cat, variables)
			hash = xxhash.xxh64()
			hasVar = False
			for var in vars:
				hasVar = True
				if verbose:
					info[cat]["details"].append(str(var))
				if names:
					hash.update(var['name'])
				if 'hash' in var:
					hash.update('#' + var['hash'])
				hash.update('@' + str(var['value']) + '/' + str(var['align']) + ':' + str(var['size']))
			if hasVar:
				info[cat]["hash"] = hash.hexdigest()

		if datatypes and self.dwarf:
			datatypes = []
			for id, size, hash in self.dwarf.iter_types(systypes):
				if size > 0:
					datatypes.append({
						"type": id,
						"size": size,
						"hash": hash
					})

			if len(datatypes) > 0:
				datatypes.sort(key = lambda x: x['type'])
				hash = xxhash.xxh64()

				info["datatypes"] = {}
				if verbose:
					info["datatypes"]["details"] = []
				for t in sortuniq_datatypes(datatypes):
					if verbose:
						info["datatypes"]["details"].append(str(t))
					hash.update(t['hash'])
				info["datatypes"]["hash"] = hash.hexdigest()

		if functions_decl:
			funcs = self.functions()
			if self.dwarf:
				funcs = self.functions_debug(filter = funcs)
			else:
				funcs = sorted([ f[0] for f in funcs ])

			if len(funcs) > 0:
				hash = xxhash.xxh64()

				info["functions"] = {}
				if verbose:
					info["functions"]["details"] = []
				for f in funcs:
					if verbose:
						info["functions"]["details"].append(f)
					hash.update(f)
				info["functions"]["hash"] = hash.hexdigest()

		return info

def get_cache_key(buildid, args):
	return f"{buildid},{args.dbgsym},{args.dbgsym_extern},{args.verbose},{args.aliases},{args.names},{args.datatypes},{args.functions},{args.writable}"

def get_data(file, args, cache):
	try:
		elf = ElfVar(file, args.base)
		key = get_cache_key(elf.buildid, args)
		if args.cache and key in cache:
			return cache[key]
		else:
			elf.load_segments()
			if args.dbgsym:
				elf.load_debug_symbols(args.dbgsym_extern, args.aliases, args.names)
			result = elf.summary(datatypes = args.datatypes, functions_decl = args.functions, writable_only = args.writable, systypes = args.systypes, names = args.names, verbose = args.verbose)
			if args.cache:
				cache[key] = result
			return result
	except Exception as e:
		print(f"Error on {file}: {str(e)}", file=sys.stderr)
		traceback.print_exc()
		return None

def simplify(data):
	if data:
		return ','.join([ f"{k}:{v['hash']}" for k,v in data.items() if type(v) is dict and 'hash' in v ]) + "\n"
	else:
		return "-\n"

def listen_socket(socket, args, cache):
	socket.listen()
	socket.setblocking(False)
	sel = selectors.DefaultSelector()
	sel.register(socket, selectors.EVENT_READ, data=None)
	buildid = re.compile(r'^[ ]*([0-9a-f]{40})[ ]*$')
	while True:
		try:
			events = sel.select(timeout=None)
			for event, mask in events:
				if event.data is None:
					conn, addr = event.fileobj.accept()
					print(f"Accepted connection from {addr}", file=sys.stderr)
					conn.setblocking(False)
					data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
					events = selectors.EVENT_READ | selectors.EVENT_WRITE
					sel.register(conn, events, data=data)
				else:
					data = event.data
					if mask & selectors.EVENT_READ:
						recv_data = event.fileobj.recv(4096)
						if recv_data:
							event.data.inb += recv_data.replace(b'\r', b'\n').replace(b'\x00', b'\n')
							while b'\n' in event.data.inb:
								p = event.data.inb.split(b'\n', maxsplit=1)
								request = p[0].decode('ascii')
								print(f"Request from {data.addr} for {request}")
								b = buildid.match(request)
								if b:
									key = get_cache_key(b.group(1), args)
									result = cache[key] if args.cache and key in cache else None
								else:
									result = get_data(request, args, cache)
								event.data.outb += bytes(simplify(result) if args.plain else json.dumps(result), 'ascii')
								event.data.inb = p[1] if len(p) > 1 else None
						else:
							print(f"Closing connection to {data.addr}")
							sel.unregister(event.fileobj)
							event.fileobj.close()
					if mask & selectors.EVENT_WRITE:
						if event.data.outb:
							if args.plain:
								print(f"Replying to {data.addr} with {event.data.outb.decode('ascii').strip()}")
							else:
								print(f"Replying to {data.addr} with {len(event.data.outb)} bytes json")
							sent = event.fileobj.send(event.data.outb)  # Should be ready to write
							event.data.outb = event.data.outb[sent:]

		except KeyboardInterrupt:
			print("Caught keyboard interrupt, exiting", file=sys.stderr)
			break
		except ConnectionError as e:
			print("Connection error: {e.error_message}", file=sys.stderr)
	sel.close()

if __name__ == '__main__':

	def dir_path(string):
		if len(string) == 0:
			return string
		path = Path(string)
		if path.is_dir():
			return str(path.resolve())
		else:
			raise NotADirectoryError(string)

	# Arguments
	parser = argparse.ArgumentParser(description="Elf Symbol Hash")
	parser.add_argument('-a', '--aliases', action='store_true', help='Include aliases (typedefs)')
	parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
	parser.add_argument('-d', '--dbgsym', action='store_true', help='use debug symbols')
	parser.add_argument('-D', '--dbgsym_extern', action='store_true', help='use external debug symbols (implies -d)')
	parser.add_argument('-b', '--base', type=dir_path, help='Path prefix for debug symbol files', default='')
	parser.add_argument('-T', '--systypes', action='store_true', help='Include types from system headers')
	parser.add_argument('-t', '--datatypes', action='store_true', help='Hash datatypes (requires debug symbols)')
	parser.add_argument('-f', '--functions', action='store_true', help='Hash API (global) functions')
	parser.add_argument('-w', '--writable', action='store_true', help='Ignore non-writable sections')
	parser.add_argument('-i', '--identical', action='store_true', help='Check if hashes of input files are identical')
	parser.add_argument('-n', '--names', action='store_true', help='Include names (complex types / members)')
	parser.add_argument('-p', '--plain', action='store_true', help='output a simple plain string containing the hashes (instead of json)')
	parser.add_argument('-c', '--cache', help='Use cache file (prefix)', default=None)
	parser.add_argument('-s', '--socket', help='Act as server on socket (unix domain socket if file, tcp socket if Host/IP(v4):Port)', default=None)
	parser.add_argument('file', type=argparse.FileType('rb'), help="ELF file with debug information", nargs='*')
	args = parser.parse_args()

	if not args.file and not args.socket:
		parser.print_usage()

	else:
		cache = shelve.open(args.cache) if args.cache else None

		if args.file:
			files = []
			for file in args.file:
				result = get_data(file, args, cache)
				if args.plain:
					print(simplify(result))
				else:
					files.append(result)
			if len(files) > 0:
				print(json.dumps(files, indent=4))
			# TODO: Compare if multiple files

		if args.socket:
			inet = re.search(r'^[ ]*((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])):([0-9]{1,5})[ ]*$', args.socket)
			if inet:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
					s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					s.bind((inet.group(1), int(inet.group(2))))
					print(f'Listening at port {inet.group(2)} on host {inet.group(1)}', file=sys.stderr)
					listen_socket(s, args, cache)
			else:
				if os.path.exists(args.socket):
					print(f'Error: socket file {args.socket} already exists', file=sys.stderr)
				else:
					with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
						s.bind((args.socket))
						print(f'Listening at unix domain socket at {args.socket}', file=sys.stderr)
						listen_socket(s, args, cache)
					os.remove(args.socket)

		if args.cache:
			cache.close()
