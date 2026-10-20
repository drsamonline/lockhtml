#!/usr/bin/env sh
# Open the LockHTML graphical interface in your browser (Linux / macOS).
#
# Runs the launcher through `sh` on purpose: the script does not need the
# executable bit set, so this works from a fresh checkout (or a filesystem that
# cannot store permission bits).
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$DIR/lockhtml.sh" gui
