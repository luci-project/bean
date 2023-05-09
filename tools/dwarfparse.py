#!/usr/bin/env python3
# Based on pyelftools example `scripts/dwarfdump.py` by Eli Bendersky (eliben@gmail.com)

import argparse
import os
import sys
import pprint
import posixpath
import traceback

from elftools import __version__
from elftools.common.exceptions import DWARFError, ELFError
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.dwarf.locationlists import LocationParser, LocationEntry, LocationExpr, LocationViewPair, BaseAddressEntry as LocBaseAddressEntry
from elftools.dwarf.ranges import RangeEntry # ranges.BaseAddressEntry collides with the one above
import elftools.dwarf.ranges
from elftools.dwarf.enums import *
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.datatype_cpp import DIE_name, describe_cpp_datatype
from elftools.dwarf.descriptions import describe_reg_name

def _to_str(val):
	if isinstance(val, bytes):
		return bytes2str(val)
	else:
		return str(val)

def _get_cu_base(cu):
	top_die = cu.get_top_DIE()
	attr = top_die.attributes
	if 'DW_AT_low_pc' in attr:
		return attr['DW_AT_low_pc'].value
	elif 'DW_AT_entry_pc' in attr:
		return attr['DW_AT_entry_pc'].value
	else:
		raise ValueError("Can't find the base IP (low_pc) for a CU")

def _addr_str_length(die):
	return die.cu.header.address_size*2

def _DIE_name(die):
	if 'DW_AT_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_name'].value)
	elif 'DW_AT_linkage_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_linkage_name'].value)
	else:
		raise DWARFError()

def _DIE_linkage_name(die):
	if 'DW_AT_linkage_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_linkage_name'].value)
	elif 'DW_AT_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_name'].value)
	else:
		raise DWARFError()

def _safe_DIE_name(die, default=None):
	if 'DW_AT_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_name'].value)
	elif 'DW_AT_linkage_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_linkage_name'].value)
	else:
		return default

def _safe_DIE_linkage_name(die, default=None):
	if 'DW_AT_linkage_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_linkage_name'].value)
	elif 'DW_AT_name' in die.attributes:
		return _to_str(die.attributes['DW_AT_name'].value)
	else:
		return default

def _desc_ref(attr, die):
	return die.cu.cu_offset + attr.raw_value

def _desc_data(attr, die):
	return attr.value

def _desc_strx(attr, die):
	return _to_str(attr.value)

FORM_DESCRIPTIONS = dict(
	DW_FORM_string=lambda attr, die: _to_str(attr.value),
	DW_FORM_strp=lambda attr, die: _to_str(attr.value),
	DW_FORM_strx1=_desc_strx,
	DW_FORM_strx2=_desc_strx,
	DW_FORM_strx3=_desc_strx,
	DW_FORM_strx4=_desc_strx,
	DW_FORM_line_strp=lambda attr, die: _to_str(attr.value),
	DW_FORM_flag_present=lambda attr, die: True,
	DW_FORM_flag=lambda attr, die: int(attr.value),
	DW_FORM_addr=lambda attr, die: attr.value,
	DW_FORM_addrx=lambda attr, die: "indexed (%08x) address = 0x%0*x" % (attr.raw_value, _addr_str_length(die), attr.value),
	DW_FORM_data1=_desc_data,
	DW_FORM_data2=_desc_data,
	DW_FORM_data4=_desc_data,
	DW_FORM_data8=_desc_data,
	DW_FORM_block1=lambda attr, die: "<0x%02x> %s " % (len(attr.value), " ".join("%02x" %b for b in attr.value)),
	DW_FORM_block2=lambda attr, die: "<0x%04x> %s " % (len(attr.value), " ".join("%02x" %b for b in attr.value)),
	DW_FORM_block4=lambda attr, die: "<0x%08x> %s " % (len(attr.value), " ".join("%02x" %b for b in attr.value)),
	DW_FORM_ref=_desc_ref,
	DW_FORM_ref1=_desc_ref, DW_FORM_ref2=_desc_ref,
	DW_FORM_ref4=_desc_ref, DW_FORM_ref8=_desc_ref,
	DW_FORM_sec_offset=lambda attr,die:  attr.value,
	DW_FORM_exprloc=lambda attr, die: _desc_expression(attr.value, die)
)

def _desc_enum(attr, enum):
	"""For attributes like DW_AT_language, physically
	int, logically an enum
	"""
	return next((k for (k, v) in enum.items() if v == attr.value), str(attr.value))

def _cu_comp_dir(cu):
	top_die = cu.get_top_DIE()
	if 'DW_AT_comp_dir' in top_die.attributes:
		return _to_str(cu.get_top_DIE().attributes['DW_AT_comp_dir'].value)
	else:
		return None

def _desc_decl_file(attr, die):
	# Filename/dirname arrays are 0 based in DWARFv5
	cu = die.cu
	if not hasattr(cu, "_lineprogram"):
		cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)
	ver5 = cu._lineprogram.header.version >= 5
	file_index = attr.value if ver5 else attr.value-1
	if cu._lineprogram and file_index >= 0 and file_index < len(cu._lineprogram.header.file_entry):
		file_entry = cu._lineprogram.header.file_entry[file_index]
		dir_index = file_entry.dir_index if ver5 else file_entry.dir_index - 1
		includes = cu._lineprogram.header.include_directory
		comp_dir = _cu_comp_dir(cu)
		if dir_index >= 0:
			dir = _to_str(includes[dir_index])
			if dir.startswith('.') and comp_dir:
				dir = posixpath.join(comp_dir, dir)
		elif comp_dir:
			dir = comp_dir
		file_name = _to_str(file_entry.name)
	else:
		raise DWARFError("Invalid source filename entry index in a decl_file attribute")
	return posixpath.join(dir, file_name)


def _desc_ranges(attr, die):
	di = die.cu.dwarfinfo
	if not hasattr(di, '_rnglists'):
		di._rangelists = di.range_lists()
	rangelist = di._rangelists.get_range_list_at_offset(attr.value, die.cu)
	try:
		base_ip = _get_cu_base(die.cu)
	except:
		return (attr.value)
	lines = []
	addr_str_len = die.cu.header.address_size*2
	for entry in rangelist:
		if isinstance(entry, RangeEntry):
			ip = 0 if entry.is_absolute else base_ip
			lines.append((ip + entry.begin_offset, ip + entry.end_offset))
		elif isinstance(entry, elftools.dwarf.ranges.BaseAddressEntry):
			base_ip = entry.base_address
		else:
			raise NotImplementedError("Unknown object in a range list")
	return lines

class LocExpr:
	def __init__(self, op=None, value=None):
		if not op:
			self.op = set()
		elif isinstance(op, set):
			self.op = op
		else:
			self.op = set([op])

		if not value:
			self.value = set()
		elif isinstance(value, set):
			self.value = value
		else:
			self.value = set([value])

	def add(self, loc):
		if loc:
			self.op |= loc.op
			self.value |= loc.value
		return self

	def add_op(self, op):
		if op:
			if isinstance(op, set):
				self.op |= op
			else:
				self.op.add(op)
		return self

	def add_value(self, value):
		if value:
			if isinstance(value, set):
				self.value |= value
			else:
				self.value.add(value)
		return self

	def __str__(self):
		return f"( 'value': {str(self.value)}, 'op': {str(self.op)} )"

	def __repr__(self):
		return str(self)

	def __add__(self, other):
		return LocExpr(self.op, self.value).add(other)

def _loc_expr_merge(locexprs):
	le = LocExpr()
	for les in locexprs:
		le.add(les)
	return le

def _desc_locations(attr, die):
	cu = die.cu
	di = cu.dwarfinfo
	if not hasattr(di, '_loclists'):
		di._loclists = di.location_lists()
	if not hasattr(di, '_locparser'):
		di._locparser = LocationParser(di._loclists)
	loclist = di._locparser.parse_from_attribute(attr, cu.header.version, die)
	if isinstance(loclist, LocationExpr):
		return _desc_expression(loclist.loc_expr, die)
	else:
		try:
			base_ip = _get_cu_base(die.cu)
		except:
			return
		l = LocExpr(value = attr.value)
		for entry in loclist:
			if isinstance(entry, LocationEntry):
				l.add(_desc_expression(entry.loc_expr, die))
		return l

# By default, numeric arguments are spelled in hex with a leading 0x
def _desc_operationarg(s, cu):
	if isinstance(s, str):
		return LocExpr( value = s )
	elif isinstance(s, int):
		return LocExpr( value = hex(s) )
	elif isinstance(s, list): # Could be a blob (list of ints), could be a subexpression
		if len(s) > 0 and isinstance(s[0], DWARFExprOp): # Subexpression
			return _loc_expr_merge([ _desc_operation(op.op, op.op_name, op.args, cu) for op in s ])
		else:
			return LocExpr(value = " ".join((hex(len(s)),) + tuple("0x%02x" % b for b in s)))

def _arch(cu):
	return cu.dwarfinfo.config.machine_arch

def _desc_reg(reg_no, cu):
	return describe_reg_name(reg_no, _arch(cu), True).upper()

def _desc_operation(op, op_name, args, cu):
	if 0x50 <= op <= 0x6f: # reg0...reg31 - decode reg name
		return LocExpr(op_name[6:], _desc_reg(op - 0x50, cu))
	elif 0x70 <= op <= 0x8f: # breg0...breg31(offset) - also decode reg name
		return LocExpr(op_name[6:], '%s%+d' % (_desc_reg(op - 0x70, cu), args[0]))
	elif op_name in ('DW_OP_fbreg', 'DW_OP_bra', 'DW_OP_skip', 'DW_OP_consts', ): # Argument is decimal with a leading sign
		return LocExpr(op_name[6:], "%+d" % (args[0]))
	elif op_name in ('DW_OP_const1s', 'DW_OP_const2s'): # Argument is decimal without a leading sign
		return LocExpr(op_name[6:], "%d" % (args[0]))
	elif op_name in ('DW_OP_entry_value', 'DW_OP_GNU_entry_value'): # No space between opcode and args
		return _desc_operationarg(args[0], cu).add_op(op_name[6:])
	elif op_name == 'DW_OP_regval_type': # Arg is a DIE pointer
		return LocExpr(op_name[6:], "%s -> 0x%08x" % (_desc_reg(args[0], cu), args[1] + cu.cu_offset))
	elif op_name == 'DW_OP_convert': # Arg is a DIE pointer
		return LocExpr(op_name[6:], args[0] + cu.cu_offset)
	elif args:
		return _loc_expr_merge(_desc_operationarg(s, cu) for s in args).add_op(op_name[6:])
	else:
		return LocExpr(op_name[6:])


def _desc_expression(expr, die):
	cu = die.cu
	if not hasattr(cu, '_exprparser'):
		cu._exprparser = DWARFExprParser(cu.structs)
	return _loc_expr_merge([ _desc_operation(op.op, op.op_name, op.args, cu) for op in cu._exprparser.parse_expr(expr) ])

def _desc_datatype(attr, die):
	try:
		return (_desc_ref(attr, die), describe_cpp_datatype(die))
	except:
		return (_desc_ref(attr, die))

def _get_origin_name(die):
	try:
		func_die = die.get_DIE_from_attribute('DW_AT_abstract_origin')
	except:
		return None

	try:
		name = _safe_DIE_linkage_name(func_die, '')
	except:
		name = None
	if not name:
		if 'DW_AT_specification' in func_die.attributes:
			name = _DIE_linkage_name(func_die.get_DIE_from_attribute('DW_AT_specification'))
		if 'DW_AT_abstract_origin' in func_die.attributes:
			name = _get_origin_name(func_die)

	return name

def _desc_origin(attr, die):
	return (attr.raw_value, _get_origin_name(die))

def _desc_spec(attr, die):
	return (_desc_ref(attr, die), _DIE_linkage_name(die.get_DIE_from_attribute('DW_AT_specification')))

def _desc_value(attr, die):
	return str(attr.value)

ATTR_DESCRIPTIONS = dict(
	DW_AT_language=lambda attr, die: _desc_enum(attr, ENUM_DW_LANG),
	DW_AT_encoding=lambda attr, die: _desc_enum(attr, ENUM_DW_ATE)[7:],
	DW_AT_accessibility=lambda attr, die: _desc_enum(attr, ENUM_DW_ACCESS),
	DW_AT_inline=lambda attr, die: _desc_enum(attr, ENUM_DW_INL),
	DW_AT_calling_convention=lambda attr, die: _desc_enum(attr, ENUM_DW_CC),
	DW_AT_decl_file=_desc_decl_file,
	DW_AT_decl_line=_desc_value,
	DW_AT_ranges=_desc_ranges,
	DW_AT_location=_desc_locations,
	DW_AT_data_member_location=lambda attr, die: _desc_data(attr, die) if attr.form.startswith('DW_FORM_data') or attr.form == 'DW_FORM_implicit_const' else _desc_locations(attr, die),
	DW_AT_frame_base=_desc_locations,
	DW_AT_type=_desc_datatype,
	DW_AT_call_line=_desc_value,
	DW_AT_call_file=_desc_decl_file,
	DW_AT_abstract_origin=_desc_origin,
	DW_AT_specification=_desc_spec
)

def _read_die(die):
	if die.is_null():
		return {}
	else:
		DIE = {
			'tag': die.tag[7:],
			'parent': die.get_parent().offset if die.get_parent() else die.offset,
			'unit': die.cu.cu_die_offset,
			'children': []
		}

		if die.has_children:
			for child in die.iter_children():
				DIE['children'].append(child.offset)

		for attr_name in die.attributes:
			attr = die.attributes[attr_name]
			try:
				if attr.name in ATTR_DESCRIPTIONS:
					val = ATTR_DESCRIPTIONS[attr.name](attr, die)
				elif attr.form in FORM_DESCRIPTIONS:
					val = FORM_DESCRIPTIONS[attr.form](attr, die)
				else:
					val = str(attr.value)
				DIE[attr_name[6:]] = val
			except:
				print(f'Parsing DIE {die.offset} attribute {attr_name} ({str(attr)}) failed', file=sys.stderr)
				traceback.print_exc()

		return DIE

def _resolve_abstract_origin(DIEs, offset):
	if 'abstract_origin' in DIEs[offset] and not 'resolved_origin' in DIEs[offset]:
		other = DIEs[offset]['abstract_origin'][0]
		if isinstance(other, int) and other in DIEs and other != offset:
			_resolve_abstract_origin(DIEs, other)
			DIEs[offset] = DIEs[other] | DIEs[offset] | { 'resolved_origin' : True }
		#else:
		#	print(f"Unable to resolve {str(other)}", file=sys.stderr)

def parse_dwarf(file):
	elffile = ELFFile(file)
	if not elffile.has_dwarf_info():
		return None

	DIEs={}
	for cu in elffile.get_dwarf_info().iter_CUs():
		for die in cu.iter_DIEs():
			if not die.is_null():
				DIEs[die.offset] = _read_die(die)

	for offset in DIEs:
		# Combine with abstract origin
		_resolve_abstract_origin(DIEs, offset)

		# Combine fields
		if 'decl_file' in DIEs[offset]:
			DIEs[offset]['decl'] = DIEs[offset]['decl_file']
			del DIEs[offset]['decl_file']
		if 'decl_line' in DIEs[offset]:
			DIEs[offset]['decl'] = (DIEs[offset]['decl'] or '[unknwon]') + ':' + str(DIEs[offset]['decl_line'])
			del DIEs[offset]['decl_line']
		if 'decl_column' in  DIEs[offset]:
			if 'decl' in DIEs[offset]:
				DIEs[offset]['decl'] += '#' + str(DIEs[offset]['decl_column'])
			del DIEs[offset]['decl_column']

	return DIEs


if __name__ == '__main__':
	for f in sys.argv[1:]:
		with open(f, "rb") as fh:
			pprint.pprint(parse_dwarf(fh))
