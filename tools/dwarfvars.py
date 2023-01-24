#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import errno
import regex
import shutil
import xxhash
import argparse
import subprocess
from pathlib import Path

from dbgsym import DebugSymbol
from dwarfparse import parse_dwarf, LocExpr

def get_loc(loc_expr, tls = False):
	if len(loc_expr.value) != 1:
		return None
	elif tls:
		for op in loc_expr.op:
			if op != 'form_tls_address' and not op.startswith('const'):
				return None
	else:
		if not len(loc_expr.op) == 1 or not 'addr' in loc_expr.op:
			return None
	return int(next(iter(loc_expr.value)),0)

def to_int(val):
	if isinstance(val, int):
		return val
	else:
		return int(val, 0)

class DwarfVars:
	def __init__(self, file, aliases = True, names = True, external_dbgsym = True, root = ''):
		self.DIEs = {}
		self.aliases = aliases
		self.names = names
		self.incomplete = False
		self.file = os.path.realpath(file)
		self.root = root
		if not os.path.exists(self.file):
			self.file = os.path.realpath(root + file)
		if len(root) > 0 and self.file.startswith(root):
			self.file = self.file[len(root):]
		self.dbgsym = None

		filepath = self.root + self.file
		if not os.path.exists(filepath):
			raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filepath)
		elif self.parse(filepath):
			self.dbgsym = filepath
		elif external_dbgsym:
			self.dbgsym = DebugSymbol(filepath, self.root).find()
			if self.dbgsym:
				self.parse(self.dbgsym)

		# Not found:
		if not self.dbgsym:
			raise FileNotFoundError(errno.ENOENT, "No Debug Information available", file)

	def parse(self, file):
		with open(file, "rb") as fh:
			self.DIEs = parse_dwarf(fh)
		return self.DIEs

	def get_die(self, type):
		if not type[0] in self.DIEs:
			print(f"Type {type} not found", file=sys.stderr)
			self.incomplete = True
			return None
		else:
			return self.DIEs[type[0]]

	def get_type(self, DIE, resolve_members = True):
		if not resolve_members and 'children' in DIE:
			# We are not able to resolve the members yet
			# so we use special keys to cache the results
			key_id = 'identifier_flat'
			key_hash = 'hash_flat'
		else:
			key_id = 'identifier'
			key_hash = 'hash'

		if not key_id in DIE:
			hash = xxhash.xxh64()
			id = ''
			size = 0
			factor = 1
			use_type_hash = False
			include_members = False

			# Hash type
			hash.update('%' + DIE['tag'])

			if DIE['tag'] == 'structure_type':
				id = 'struct'
				include_members = True
			elif DIE['tag'] == 'class_type':
				id = 'class'
				include_members = True
			elif DIE['tag'] == 'union_type':
				id = 'union'
				include_members = True
			elif DIE['tag'] == 'enumeration_type':
				id = 'enum'
				include_members = True
			elif DIE['tag'] == 'const_type':
				# Ignore const if not alias
				if self.aliases or not 'type' in DIE:
					id = 'const'
				else:
					use_type_hash = True
			elif DIE['tag'] == 'typedef':
				# ignore typedef if not alias
				if self.aliases or not 'type' in DIE:
					identifier = 'typedef'
				else:
					use_type_hash = True
			elif DIE['tag'] == 'pointer_type':
				resolve_members = False

			if 'name' in DIE and self.names:
				hash.update('.' + DIE['name'])
				if len(id) > 0:
					id += ' '
				id += DIE['name']
			elif 'linkage_name' in DIE and self.names:
				hash.update('.' + DIE['linkage_name'])
				if len(id) > 0:
					id += ' '
				id += DIE['linkage_name']

			if include_members and resolve_members:
				id += ' { '
				for child in self.iter_children(DIE):
					if child['tag'] == 'member':
						child_id, child_size, child_hash = self.get_type(child, resolve_members)
						hash.update('>' + child_hash)
						id += child_id
						# Struct members contain offset (due to padding)
						if 'data_member_location' in child:
							hash.update('@' + str(child['data_member_location']))
							id += ' @ ' + str(child['data_member_location'])
						id += '; '
					elif child['tag'] == 'enumerator':
						hash.update('>' + child['name']+ '=' + str(child['const_value']))
						id += child['name'] + ' = ' + str(child['const_value']) + ', '
				id += '}'

			if 'type' in DIE:
				type_DIE = self.get_die(DIE['type'])
				if type_DIE:
					type_id, type_size, type_hash = self.get_type(type_DIE, resolve_members)
					id += '(' + type_id + ')' if len(id) > 0 else type_id
					size = to_int(type_size)
					# TODO with partial unit type_hash might be random
					if size != 0 or len(type_id) != 0:
						hash.update('#' + type_hash)
				else:
					type_hash = ''

			if DIE['tag'] == 'pointer_type':
				id += '*'
			elif DIE['tag'] == 'array_type':
				for child in self.iter_children(DIE):
					if child['tag'] == 'subrange_type':
						lower = to_int(child.get('lower_bound', 0))
						if not isinstance(lower, int):
							lower = 0;
						upper = to_int(child.get('upper_bound', 0))
						if not isinstance(upper, int):
							upper = 0;
						hash.update('[' + str(lower) + ':' + str(upper) + ']')
						subrange = upper - lower + 1
						id += '[' + str(subrange) + ']'
						factor *= subrange

			if 'byte_size' in DIE:
				size = DIE['byte_size']

			if 'encoding' in DIE:
				assert factor == 1
				hash.update(DIE['encoding'])
				enc =  str(size) + " byte " + DIE['encoding']
				id += '(' + enc + ')' if len(id) > 0 else enc

			# TODO: hash.update(':' + str(size) + '*' + str(factor))
			hash.update(':' + str(factor))
			DIE[key_id] = id
			if 'total_size' in DIE:
				assert(to_int(DIE['total_size']) == factor * size)
			else:
				DIE['total_size'] = factor * size
			DIE[key_hash] = type_hash if use_type_hash else hash.hexdigest()

		return DIE[key_id], to_int(DIE['total_size']), DIE[key_hash]


	def get_def(self, DIE, resolve_members = True, skip_const = False):
		size = 0
		factor = 1
		include_members = False
		cdef = ''

		if DIE['tag'] == 'structure_type':
			cdef = 'struct'
			include_members = True
		elif DIE['tag'] == 'class_type':
			cdef = 'class'
			include_members = True
		elif DIE['tag'] == 'union_type':
			cdef = 'union'
			include_members = True
		elif DIE['tag'] == 'enumeration_type':
			cdef = 'enum'
			include_members = True
		elif DIE['tag'] == 'const_type':
			if not skip_const:
				cdef = 'const '
				skip_const = True
		elif DIE['tag'] == 'pointer_type':
			resolve_members = False

		name = None
		if 'name' in DIE:
			name = DIE['name']
		elif 'linkage_name' in DIE:
			name = DIE['linkage_name'];

		if include_members and resolve_members:
			if name:
				cdef += ' ' + name
				name = None
			cdef += ' { '
			for child in self.iter_children(DIE):
				if child['tag'] == 'member':
					child_cdef, child_size, child_factor = self.get_def(child, resolve_members, False)
					cdef += child_cdef
					if child_factor != 1:
						cdef += '[' + str(child_factor) + ']'
					cdef += '; '
					if 'data_member_location' in child:
						cdef += ' /* offset ' + str(child['data_member_location']) + ' */'
				elif child['tag'] == 'enumerator':
					cdef += child['name'] + ' = ' + str(child['const_value']) + ', '
			cdef += '}'

		if 'type' in DIE and (DIE['tag'] != 'typedef' or self.aliases):
			def_DIE = self.get_die(DIE['type'])
			if def_DIE:
				type_cdef, type_size, factor = self.get_def(def_DIE, resolve_members, skip_const)
				cdef += type_cdef
				size = type_size

		if DIE['tag'] == 'pointer_type':
			if not 'type' in DIE or len(cdef) == 0:
				cdef += 'void'
			cdef += '*'
			factor = 1
		elif DIE['tag'] == 'array_type':
			for child in self.iter_children(DIE):
				if child['tag'] == 'subrange_type':
					factor *= to_int(child.get('upper_bound', 0)) - to_int(child.get('lower_bound', 0)) + 1

		if name and self.names and (DIE['tag'] != 'typedef' or not self.aliases):
			if len(cdef) > 0:
				cdef += ' '
			cdef += name
			if factor != 1:
				cdef += '[' + str(factor) + ']'
				factor = 1

		if 'byte_size' in DIE:
			size = to_int(DIE['byte_size'])

		if 'total_size' in DIE:
			assert(to_int(DIE['total_size']) == factor * size)
		else:
			DIE['total_size'] = factor * size

		return cdef, to_int(DIE['total_size']), factor


	def get_vars(self, tls = False):
		variables = []
		for ID, DIE  in self.DIEs.items():
			if DIE['tag'] == 'variable' and 'location' in DIE and 'type' in DIE:
				addr = get_loc(DIE['location'], tls)
				if addr is None or (addr == 0 and not tls):
					continue
				type_DIE = self.get_die(DIE['type'])
				if not type_DIE:
					continue
				typename, size, hash = self.get_type(type_DIE)
				variables.append({
					'name': DIE['name'] if 'name' in DIE else "[anonymous]",
					'value': addr,
					'type': typename,
					'unit': DIE['unit'],
					'size': size,
					'external': DIE['external'] if 'external' in DIE else False,
					'hash': hash,
					'source': DIE['decl'] if 'decl' in DIE else ''
				})
		return variables


	def iter_children(self,  DIE):
		if 'children' in DIE:
			for CID in DIE['children']:
				yield self.DIEs[CID]


	def iter_types(self, include_system_types = False):
		type_tags = ['structure_type', 'class_type', 'union_type', 'enumeration_type']
		for ID, DIE in self.DIEs.items():
			if DIE['tag'] in type_tags and (include_system_types or not 'decl' in DIE or not DIE['decl'].startswith(('/usr/lib/gcc/', '/usr/local/include/', '/usr/include/'))):
				yield self.get_type(DIE)


	def iter_globals(self):
		type_tags = ['variable', 'structure_type', 'class_type', 'union_type', 'enumeration_type']
		for ID, DIE in self.DIEs.items():
			if DIE['tag'] in type_tags and ('name' in DIE or 'linkage_name' in DIE):
				cdef, size, factor = self.get_def(DIE)
				assert(factor == 1)
				if size > 0:
					yield cdef, size, DIE


	def iter_func(self, only_external = False):
		type_tags = []
		for ID, DIE in self.DIEs.items():
			if 'declaration' in DIE and DIE['declaration']:
				continue
			elif only_external and not ('external' in DIE and DIE['external']):
				continue
			elif DIE['tag'] == 'subprogram':
				if 'linkage_name' in DIE:
					name = DIE['linkage_name']
				elif 'name' in DIE:
					name = DIE['name']
				else:
					continue
				full_hash = xxhash.xxh64()

				ret = 'void'
				if 'type' in DIE and DIE['type'][0] in self.DIEs:
					ret, size, hash = self.get_type(self.DIEs[DIE['type'][0]])
					full_hash.update(hash)

				full_hash.update(name)

				params = []
				for param in self.iter_children(DIE):
					if param['tag'] == 'formal_parameter':
						type, size, hash = self.get_type(param)
						full_hash.update(hash)
						params.append(type)

				addr = DIE['low_pc'] if 'low_pc' in DIE else 0
				yield name, addr, ret, ', '.join(params), full_hash.hexdigest()


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
	parser = argparse.ArgumentParser(description="Dwarf Variables Dump")
	parser.add_argument('-a', '--aliases', action='store_true', help='Include aliases (typedefs)')
	parser.add_argument('-n', '--names', action='store_true', help='Include names (complex types / members)')
	parser.add_argument('-b', '--base', type=dir_path, help='Path prefix for debug symbol files', default='')
	subparsers = parser.add_subparsers(title='Extract', dest='extract', required=True, help='Information to extract')
	parser.add_argument('file', metavar="FILE", help="ELF file with debug information")
	parser_var = subparsers.add_parser('variables', help='All static variables')
	parser_var.add_argument('-s', '--source', action='store_true', help='Include source code reference comment')
	parser_var.add_argument('-t', '--tls', action='store_true', help='Extract TLS variables')
	parser_var.add_argument('-j', '--json', action='store_true', help='Output as JSON')
	parser_data = subparsers.add_parser('datatypes', help='All data types (struct, union, enum) from file')
	parser_data.add_argument('-t', '--systypes', action='store_true', help='Include types from system headers')
	parser_glob = subparsers.add_parser('globals', help='All global data types')
	parser_func = subparsers.add_parser('functions', help='All functions')
	parser_func.add_argument('-e', '--extern', action='store_true', help='Only external functions')
	args = parser.parse_args()

	if not os.path.exists(args.file):
		print(f"Input file '{args.file}' does not exist!", file=sys.stderr)
		sys.exit(1)

	dwarf = DwarfVars(args.file, aliases = args.aliases, names = args.names, root = args.base)
	if args.extract == 'variables':
		variables = sorted(dwarf.get_vars(args.tls), key=lambda i: i['value'])
		if args.json:
			print(variables)
		else:
			for var in variables:
				extern = 'extern ' if var['external'] else ''
				source = f" /* {var['source']} */" if args.source else ''
				print(f"{extern}{var['name']}({var['type']}) {var['size']} byte @ {var['value']:016x} # {var['hash']} {source}")
	elif args.extract == 'datatypes':
		# TODO: Sort by compile unit
		full_hash = xxhash.xxh64()
		for id, size, hash in dwarf.iter_types(args.systypes):
			full_hash.update(hash)
			print(f"{id} {size} bytes # {hash}")
		print(full_hash.hexdigest())
	elif args.extract == 'globals':
		for cdef, size, DIE in dwarf.iter_globals():
			print(f"{cdef};  // {size} bytes")
	elif args.extract == 'functions':
		for name, addr, ret, params, hash in dwarf.iter_func(args.extern):
			print(f"{ret} {name}({params}) # {hash}")
