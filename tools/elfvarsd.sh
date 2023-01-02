#!/bin/bash

ELFVARSARGS=( '-d' '-D' '-t' '-f' '-w' '-p' )
CACHEPREFIX=".elfvarsd-cache"
DEFAULTSOCKET="0.0.0.0:9001"

BEAN_TOOLS=$(dirname -- "$(readlink -f "${BASH_SOURCE[0]}")" )

if [ -z ${NODEBUG+exist} ]; then
	NODEBUG=0
fi

declare -a BASEDIRS
while [[ $# -gt 0 ]] ; do
	case "$1" in
		-h)
			echo "Inspect (analyze) all files in base directories on start, cache the results and start elfvars as daemon"
			echo
			echo "	Usage: $0 [-h] [-N] [-c CACHEPREFIX] [SOCKET [BASE DIRs]] [-- ELFVARS-ARGS]"
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

		-N)
			shift
			NODEBUG=1
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

if [[ $NODEBUG -eq 1 ]] ; then
	echp "Not using debug symbols!"
	for index in "${!ELFVARSARGS[@]}" ; do
		if [[ "${ELFVARSARGS[$i],,}" == "-d" ]] ; then
			unset -v 'ELFVARSARGS[$i]'
		fi
	done
	CACHEPREFIX+='-nodebug'
fi

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
