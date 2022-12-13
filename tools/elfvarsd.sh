#!/bin/bash

ELFVARSARGS=( '-d' '-D' '-t' '-w' '-p' )
CACHEPREFIX=".elfvarsd-cache"
DEFAULTSOCKET="0.0.0.0:9001"

BEAN_TOOLS=$(dirname -- "$(readlink -f "${BASH_SOURCE[0]}")" )

declare -a BASEDIRS
while [[ $# -gt 0 ]] ; do
	case "$1" in
		-h)
			echo "Inspect (analyze) all files in base directories on start, cache the results and start elfvars as daemon"
			echo
			echo "	Usage: $0 [-h] [-c CACHEPREFIX] [SOCKET [BASE DIRs]] [-- ELFVARS-ARGS]"
			echo
			echo "A socket value 'cache' will only cache the base dirs,"
			echo "but not open a listen socket."
			echo
			echo "Default cache prefix is '${CACHEPREFIX}'"
			echo "Default socket is '${DEFAULTSOCKET}'"
			echo "Default ELFVARS-ARGS are '${ELFVARSARGS[@]}'"
			exit 0
			;;

		-c)
			shift
			CACHEPREFIX=$1
			;;
		--)
			shift
			ELFVARSARGS=$@
			break
			;;
		*)
			if [[ -z "${SOCKET+empty}" ]]; then
				SOCKET=$1
			else
				BASEDIRS+=( $1 )
			fi
			;;
	esac
	shift
done

ELFVARSARGS+=( '-c' "${CACHEPREFIX}" )

echo "Preprocessing (caching) ${#BASEDIRS[@]} directories..." >&2
for BASEDIR in "${BASEDIRS[@]}" ; do
	FILES=( $(find -L "${BASEDIR}" -type f -name '*.so*' -exec file -L {} + | grep "shared object" | sed 's/: .*//') )
	echo "Analyzing ${#FILES[@]} files in ${BASEDIR}..." >&2
	${BEAN_TOOLS}/elfvars.py ${ELFVARSARGS[@]} -b "${BASEDIR}" "${FILES[@]}"
done


ELFVARSARGS+=( '-s' "${SOCKET:=$DEFAULTSOCKET}" )
if [[ "${SOCKET,,}" != "cache" ]] ; then
	echo "Starting elfvars with '${ELFVARSARGS[@]}' "
	exec ${BEAN_TOOLS}/elfvars.py ${ELFVARSARGS[@]}
fi
