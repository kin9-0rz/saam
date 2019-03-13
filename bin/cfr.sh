#!/usr/bin/env bash

# Try to find a valid python3 command, preferring pypy if available
function guess {
	if [ -z "$PYTHON" ]; then
		result=$($1 -c "print(range)" 2>/dev/null)
		if [ "$result" = "<class 'range'>" ]; then
			PYTHON=$1
		fi
	fi
}

guess "python3"

if [ -z "$PYTHON" ]; then
	echo "Unable to find python3 on path"
else
	# Find location of this bash script, and set its directory as the PYTHONPATH
	TMP=${BASH_SOURCE%/bin*}
	export PYTHONPATH=${TMP}

	# Now execute the actual program
	exec $PYTHON -O -m saam.decompiler.cfr "$@"
fi
