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
parser.add_argument('-l', '--lib', help='filter library names (by regex)', nargs='*')
parser.add_argument('-d', '--verdir', help='filter version directories (by regex)', nargs='*')
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

console = Console()
tree = Tree(escape(base.name))
start=next(iter(sorted_dirs))
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
		print(f"Executing of {args} failed: {e.message}", file=sys.stderr)
		return {}

def add_details(text, data, section, dim):
	changed = data['changed-external']['added']['size'] != 0 or data['changed-external']['removed']['size'] != 0
	highlight = section in [ 'bss', 'data', 'tdata', 'tbss', 'init' ];
	if args.verbose > 1 or (args.verbose == 1 and changed):
		text.append(Text(f"\n.{section}", Style(italic=not changed, dim=dim, bold=highlight)))
	if args.verbose > 1:
		text.append(Text("\n   {count}: {size}B".format_map(data['total']), Style(italic=not changed, dim=dim)))
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


for o in sorted_objs:
	table = Table(title=Text.assemble(str(o.parent), "/", (str(o.name), Style(bold=True))), show_header=True, header_style="bold")
	table.add_column("Package", style="dim")

	with Progress(transient=True) as progress:
		task = progress.add_task(f"Processing {escape(o.name)}...", total=(len(dirs) ** 2 + len(dirs)))

		with multiprocessing.Pool(processes=args.nproc) as pool:
			diffs={}
			elfvars={}
			for a in sorted_dirs:
				tmpdiff={}
				elfvars[str(a.name)] = pool.apply_async(exec_json, (args.hashtool, '-r', str(a), '-d', '-w', '-D', '-t',  str(a.joinpath(o))), callback=lambda r : progress.advance(task))
				for b in sorted_dirs:
					tmpdiff[str(b.name)] = pool.apply_async(exec_json, (args.difftool, str(a.joinpath(o)), str(b.joinpath(o))), callback=lambda r : progress.advance(task))
				diffs[str(a.name)] = tmpdiff
				table.add_column(Text(escape(a.name), justify="center", overflow="fold"))

			hashval={}
			for obj, data in elfvars.items():
				d = data.get()
				hashval[obj] = {k: v['hash'] for k,v in d[0].items() if type(v) is dict and 'hash' in v } if len(d) > 0 else {}

			for coltitle, cells in diffs.items():
				line=[Text(escape(coltitle), overflow="fold")]
				last = None
				for obj, thread in cells.items():
					result = thread.get()
					dim = natsorted([obj, coltitle], alg=ns.IGNORECASE, key=str)[0] == obj
					text=[]
					hashsuccess = not hashval[coltitle] or not hashval[obj] or hashval[coltitle] == hashval[obj]
					for section, data in result.items():
						if section == "patchable":
							if data and hashsuccess:
								t = "update"
								c = "green"
							else:
								t = "restart"
								c = "red"

							if obj == coltitle:
								t = "(" + t + ")"
							text.append(Text(t, Style(color=c, dim=dim, underline= last == coltitle)))

						elif section == "build-id":
							changed = data['added'] != data['removed']
							if args.verbose > 1 or (args.verbose == 1 and changed):
								text.append(Text(f"\n.build-id", Style(italic=not changed, dim=dim)))
							if args.verbose > 1:
								text.append(Text("\n {added}".format_map(data), Style(color='light_green', dim=dim)))
								text.append(Text("\n {removed}".format_map(data), Style(color='light_coral', dim=dim)))

						elif 'total' in data:
							add_details(text, data, section, obj <= coltitle)

					if len(text) == 0:
						text.append(Text("error", Style(color="red")))
					elif args.verbose >= 1:
						if hashval[obj]:
							if args.verbose > 1 or (args.verbose == 1 and hashsuccess):
								if not 'debug' in hashval[obj]:
									# No debug symbols
									hashstatus = ' *'
								elif 'debug-incomplete' in hashval[obj] and hashval[obj]['debug-incomplete']:
									# Errors during hashing
									hashstatus = ' !'
								else:
									hashstatus = ''
								text.append(Text(f"\n.debug{hashstatus}", Style(italic=hashsuccess, dim=dim, bold=True)))
							if args.verbose > 2:
								for k,v in hashval[obj].items():
									n = 'dt' if k == 'datatypes' else k
									text.append(Text(f"\n {n}:{v}", Style(color='light_coral' if k in hashval[coltitle] and hashval[coltitle][k] != v else None, dim=dim)))


						text.append("\n");
					line.append(Text.assemble(*text))

					last = obj

				table.add_row(*line)


	console.print(table, end='\n')
	if args.output:
		output.print(table, end='\n')

if args.output:
	for handle in args.output:
		with handle as f:
			print("(Exporting to {f.name}...", file=sys.stderr)
			if f.name.lower().endswith(('htm','html')):
				f.write(output.export_html(clear=False))
			elif f.name.lower().endswith(('svg')):
				f.write(output.export_svg(title=str(base),clear=False))
			else:
				f.write(output.export_text(clear=False))
	devnull.close()
