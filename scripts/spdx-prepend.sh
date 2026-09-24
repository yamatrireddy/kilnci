#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Prepends the SPDX header to generated files that lack it (generators do not
# emit it). usage: spdx-prepend.sh <comment-prefix> <file>...
set -euo pipefail
prefix=$1; shift
for f in "$@"; do
  if ! head -n 1 "$f" | grep -q "SPDX-License-Identifier"; then
    { printf '%s SPDX-License-Identifier: Apache-2.0\n\n' "$prefix"; cat "$f"; } > "$f.tmp"
    mv "$f.tmp" "$f"
  fi
done
