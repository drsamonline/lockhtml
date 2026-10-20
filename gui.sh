#!/usr/bin/env sh
# Open the LockHTML graphical interface in your browser (Linux / macOS).
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$DIR/lockhtml.sh" gui
