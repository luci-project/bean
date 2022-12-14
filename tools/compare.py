#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from natsort import natsorted, ns
from rich.progress import Progress
from rich.console import Console
from rich.markup import escape
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
import multiprocessing
import subprocess
import argparse
import json
import sys
import os
import re

def dir_path(string):
	if Path(string).is_dir():
		return string
	else:
		raise NotADirectoryError(string)

parser = argparse.ArgumentParser(description="Compare different versions of a binary to see if they can be updated")
parser.add_argument("base", type=dir_path, help="the base directory containing all versions of a package")
parser.add_argument('--difftool', help="the bean update check tool", default="bean-diffstat")
parser.add_argument('--hashtool', help="the bean dwarf variable hash tool", default="bean-elfvars")
parser.add_argument('-m', '--matrix', help='Compare each version with each other', action='store_true')
parser.add_argument('-l', '--lib', help='filter library names (by regex)', nargs='*')
parser.add_argument('-s', '--dbgsym', action='store_true', help='use (external?) debug symbols in difftool')
parser.add_argument('-d', '--dependencies', action='store_true', help='recursively check all dependencies')
parser.add_argument('-r', '--relocations', action='store_true', help='resolve internal relocations')
parser.add_argument('-D', '--verdir', help='filter version directories (by regex)', nargs='*')
parser.add_argument('-o', '--output', type=argparse.FileType('w'), help='export output to file[s] (html/svg/text)', nargs='*')
parser.add_argument('-n', '--nproc', type=int, help="Number of worker Threads", default=None)
parser.add_argument('-v', '--verbose', action='count', default=0)


args = parser.parse_args()

base=Path(args.base)

# Gather files and directories
dirs=set()
objs=set()
for d in base.glob("*/"):
	if d.is_dir() and not d.name.startswith('.'):
		if args.verdir:
			for verdir in args.verdir:
				if re.search(r'^{}$'.format(verdir), d.name):
					break
			else:
				continue

		o=set()
		for f in d.rglob('*.so*'):
			if f.is_file():
				with open(f, mode="rb") as elf:
					if elf.read(4) == b"\x7fELF":
						if args.lib:
							for lib in args.lib:
								if re.search(r'^{}$'.format(lib), f.name):
									break
							else:
								continue
						o.add(f.relative_to(d))
		if len(dirs) == 0:
			objs=o
		else:
			objs = objs.intersection(o)
		dirs.add(d)

sorted_dirs = natsorted(dirs, alg=ns.IGNORECASE, key=str)
sorted_objs = natsorted(objs, alg=ns.IGNORECASE, key=str)

# Print tree
def walk_directory(directory: Path, tree: Tree, base: str, objs: set) -> None:
	for path in sorted(Path(directory).iterdir(), key=lambda path: (path.is_file(), path.name.lower())):
		if path.name.startswith('.'):
			continue
		elif path.is_dir():
			if not path.is_symlink():
				walk_directory(path, tree.add(escape(path.name), style=Style(dim=True)), base, objs)
		elif path.relative_to(base) in objs:
			tree.add(escape(path.name), style=Style(dim=False, bold=True))
		elif not path.name.endswith( ('.diff', '.dsc')):
			tree.add(escape(path.name))

console = Console(highlight=False)
tree = Tree(escape(base.name))
start = next(iter(sorted_dirs))
walk_directory(start, tree, start, objs)
console.print(tree)


if args.output:
	devnull = open(os.devnull, 'w')
	output = Console(width=45*len(sorted_dirs) + 50,file=devnull,force_terminal=False,force_jupyter=False,force_interactive=False,record=True)
	output.print(tree)

# check if updatable
def exec_json(*args):
	try:
		p = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
		if p.returncode == 0:
			return json.loads(p.stdout)
		else:
			return {}
	except Exception as e:
		print(f"Executing of {args} failed: {e}", file=sys.stderr)
		return {}

def add_details(text, data, section, dim):
	changed = data['changed-external']['added']['size'] != 0 or data['changed-external']['removed']['size'] != 0
	highlight = section in [ 'bss', 'data', 'tdata', 'tbss', 'init' ];
	if args.verbose > 1 or (args.verbose == 1 and changed):
		text.append(Text(f"\n.{section}", Style(italic=not changed, color='white' if changed else None, dim=dim, bold=highlight)))
	if args.verbose > 1:
		#print(section, data)
		text.append(Text("\n   {count}: {size}B".format_map(data['total']), Style(italic=not changed, color='white' if changed else None, dim=dim)))
		if args.verbose > 3:
			if data['changed-internal']['added']['size'] != 0:
				text.append(Text("\n(+ {count}:  {size}B)".format_map(data['changed-internal']['added']), Style(color='light_green', dim=dim)))
			if data['changed-internal']['removed']['size'] != 0:
				text.append(Text("\n(- {count}: {size}B)".format_map(data['changed-internal']['removed']), Style(color='light_coral', dim=dim)))
		if args.verbose > 2:
			if data['changed-external']['added']['size'] != 0:
				text.append(Text("\n + {count}: {size}B".format_map(data['changed-external']['added']), Style(color='light_green', dim=dim)))
			if data['changed-external']['removed']['size'] != 0:
				text.append(Text("\n - {count}: {size}B".format_map(data['changed-external']['removed']), Style(color='light_coral', dim=dim)))


def build_cell(result, obj, base, hashval, hashdbg, highlight = False):
	dim = natsorted([obj, base], alg=ns.IGNORECASE, key=str)[0] == obj
	text=[]
	patchable = None
	hashsuccess = not hashval[base] or not hashval[obj] or hashval[base] == hashval[obj]
	for section, data in result.items():
		if section == "patchable":
			if data and hashsuccess:
				t = "update"
				c = "green"
				patchable = True
			else:
				t = "restart"
				c = "red"
				patchable = False

			if obj == base:
				t = "(" + t + ")"
			text.append(Text(t, Style(color=c, dim=dim, underline=highlight)))

		elif section == "build-id":
			changed = data['added'] != data['removed']
			if args.verbose > 1 or (args.verbose == 1 and changed):
				text.append(Text(f"\n.build-id", Style(italic=not changed, color='white' if changed else None, dim=dim)))
			if args.verbose > 1:
				color = 'light_green' if args.verbose > 2 else 'white'
				text.append(Text("\n {added}".format_map(data), Style(color=color if changed else None, dim=dim)))
				if args.verbose > 2 and changed:
					text.append(Text("\n {removed}".format_map(data), Style(color='light_coral', dim=dim)))

		elif 'total' in data:
			add_details(text, data, section, obj <= base)

	if len(text) == 0:
		text.append(Text("error", Style(color="red")))
	elif args.verbose >= 1:
		if hashval[obj]:
			if args.verbose > 1 or (args.verbose == 1 and hashsuccess):
				if not 'debug' in hashdbg[obj]:
					# No debug symbols
					hashstatus = ' *'
				elif 'debug-incomplete' in hashdbg[obj] and hashdbg[obj]['debug-incomplete']:
					# Errors during hashing
					hashstatus = ' !'
				else:
					hashstatus = ''
				text.append(Text(f"\n.debug{hashstatus}", Style(italic=hashsuccess, color='white' if not hashsuccess else None, dim=dim, bold=True)))
			if args.verbose > 1:
				for k,v in hashval[obj].items():
					n = 'dt' if k == 'datatypes' else k
					changed = k in hashval[base] and hashval[base][k] != v
					color = 'light_green' if args.verbose > 2 else 'white'
					text.append(Text(f"\n {n}:{v}", Style(color=color if changed else None, dim=dim)))
					if args.verbose > 2 and changed:
						text.append(Text(f"\n {n}:{hashval[base][k] }", Style(color='light_coral', dim=dim)))

		text.append("\n");

	return text, patchable


for o in sorted_objs:
	table = Table(title=Text.assemble(str(o.parent), "/", (str(o.name), Style(bold=True))), show_header=True, header_style="bold")
	if args.matrix:
		table.add_column("Package", style="dim")

	patchcount = 0

	with Progress(transient=True) as progress:
		task = progress.add_task(f"Processing {escape(o.name)}...", total=(len(dirs) ** (1 + int(args.matrix)) + len(dirs)))

		with multiprocessing.Pool(processes=args.nproc) as pool:
			diffs={}
			elfvars={}
			last = None
			diffflags = ()
			if args.dependencies:
				diffflags = (*diffflags, '-d')
			if args.relocations:
				diffflags = (*diffflags, '-r')

			for a in sorted_dirs:
				elfvars[str(a.name)] = pool.apply_async(exec_json, (args.hashtool, '-b', str(a), '-d', '-w', '-D', '-t',  str(a.joinpath(o))), callback=lambda r : progress.advance(task))
				if args.matrix:
					tmpdiff={}
					for b in sorted_dirs:
						flags = (*diffflags, '-s', '-b', str(a), '-b', str(b)) if args.dbgsym else diffflags
						tmpdiff[str(b.name)] = pool.apply_async(exec_json, (args.difftool, *flags, str(a.joinpath(o)), str(b.joinpath(o))), callback=lambda r : progress.advance(task))
					diffs[str(a.name)] = tmpdiff
				else:
					flags = (*diffflags, '-s', '-b', str(last or a), '-b', str(a)) if args.dbgsym else diffflags
					diffs[str(a.name)] = pool.apply_async(exec_json, (args.difftool, *flags, str((last or a).joinpath(o)), str(a.joinpath(o))), callback=lambda r : progress.advance(task))
				table.add_column(Text(escape(a.name), justify="center", overflow="fold"))
				last = a

			hashval={}
			hashdbg={}
			for obj, data in elfvars.items():
				d = data.get()
				if len(d) > 0 and d[0]:
					i = d[0].items()
					hashval[obj] = {k: v['hash'] for k,v in i if type(v) is dict and 'hash' in v}
					hashdbg[obj] = {k: v for k, v in i if k.startswith('debug') }
				else:
					hashval[obj] = {}
					hashdbg[obj] = {}

			if args.matrix:
				for coltitle, cells in diffs.items():
					line = [Text(escape(coltitle), overflow="fold")]
					last = None
					for obj, thread in cells.items():
						text, patchable = build_cell(thread.get(), obj, coltitle, hashval, hashdbg, last == coltitle)
						if last and last == coltitle and patchable:
							patchcount = patchcount + 1
						line.append(Text.assemble(*text))
						last = obj
					table.add_row(*line)
			else:
				line = []
				last = None
				for obj, thread in diffs.items():
					text, patchable = build_cell(thread.get(), obj, last or obj, hashval, hashdbg)
					if last and patchable:
						patchcount = patchcount + 1
					line.append(Text.assemble(*text))
					last = obj
				table.add_row(*line)

	console.print(table, end='\n')
	summary = f"For [b]{str(o.name)}[/b], [light_green]{patchcount}[/light_green] of {len(sorted_dirs) - 1} versions ([light_green]{round(100*patchcount/(len(sorted_dirs) - 1))}%[/light_green]) can be live patched"
	settings = []
	if args.dependencies:
		settings.append("recusive symbol dependency checks")
	if args.relocations:
		settings.append("internal relocation resolving")
	if args.dbgsym:
		settings.append("(external?) debug symbols")
	if len(settings) > 2:
		summary += " with " + ", ".join(settings[:-1]) + " and " + settings[-1]
	elif len(settings) > 0:
		summary += " with " + " and ".join(settings)
	console.print(f"[i]Summary:[/i] {summary}!\n", end='\n')
	if args.output:
		output.print(table, end='\n')
		output.print(summary, end='\n')

if args.output:
	for handle in args.output:
		with handle as f:
			print(f"(Exporting to {f.name}...", file=sys.stderr)
			if f.name.lower().endswith(('htm','html')):
				f.write(output.export_html(clear=False))
			elif f.name.lower().endswith(('svg')):
				f.write(output.export_svg(title=str(base),clear=False))
			else:
				f.write(output.export_text(clear=False))
	devnull.close()
