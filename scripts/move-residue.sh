#!/usr/bin/env bash
# What did each file MOVE itself change?
#
# The sixteen-issue Core refactor series, closed by #360, relocated 325 Go
# files between the three modules. Reviewing that as a base-to-head diff blames
# each move for every later commit that touched the file, so a bug fix landed
# after a package moved reads as part of the move. This walks the series commit
# by commit instead, finds each rename where it actually happened, and compares
# parent:old against commit:new with the package clause and the import block
# stripped. What survives is content that commit changed while moving the file,
# which is the only thing "accidental logic change" can mean.
#
# Two boundaries, reported rather than hidden:
#
#   - strip removes the whole import block, so a move that also repointed an
#     import reads as pure. That is right when a companion package moved in the
#     same series and wrong to leave unsaid, so every import delta is printed and
#     the ones with no other residue are listed separately: nothing else presents
#     those for review.
#   - only R records are walked, so a move git did not pair is invisible. A
#     second detection pass at -M10% reports any rename the default threshold
#     missed. A split is invisible here by construction -- the source stays and
#     the destination is an add, so there is no rename to read -- and has to be
#     verified at the commit that lands it instead.
#
# Deliberately not wired into any test tier: it reviews history, which is fixed,
# so running it on every build would spend minutes proving a constant (#360).
#
# Usage: move-residue.sh [base] [head]
set -uo pipefail
BASE="${1:-$(git log --format=%H --diff-filter=A -- ARCHITECTURE.md | tail -1)^}"
HEAD_REF="${2:-HEAD}"

strip() {
  awk '
    /^package /     { next }
    /^import \($/   { inimp=1; next }
    inimp && /^\)$/ { inimp=0; next }
    inimp           { next }
    /^import "/     { next }
    { print }
  '
}

imports() {
  awk '
    /^import \($/   { inimp=1; next }
    inimp && /^\)$/ { inimp=0; next }
    inimp           { if ($0 ~ /[^ \t]/) print $0 }
    /^import "/     { print }
  ' | sed 's/^[[:space:]]*//' | sort
}

impfile=$(mktemp); purefile=$(mktemp); pairfile=$(mktemp); extrafile=$(mktemp)
trap 'rm -f "$impfile" "$purefile" "$pairfile" "$extrafile"' EXIT

moves=0; clean=0; dirty=0; impchanged=0; impclean=0
for c in $(git rev-list --reverse "$BASE".."$HEAD_REF"); do
  : > "$pairfile"
  while IFS=$'\t' read -r status old new; do
    case "$status" in R*) ;; *) continue;; esac
    case "$old" in *.go) ;; *) continue;; esac
    printf '%s\t%s\n' "$old" "$new" >> "$pairfile"
    moves=$((moves+1))
    rawa=$(git show "$c^:$old" 2>/dev/null)
    rawb=$(git show "$c:$new"  2>/dev/null)
    a=$(printf '%s\n' "$rawa" | strip)
    b=$(printf '%s\n' "$rawb" | strip)
    ia=$(printf '%s\n' "$rawa" | imports)
    ib=$(printf '%s\n' "$rawb" | imports)
    if [ "$ia" != "$ib" ]; then
      impchanged=$((impchanged+1))
      {
        printf '%s  %s -> %s\n' "${c:0:8}" "$old" "$new"
        diff <(printf '%s\n' "$ia") <(printf '%s\n' "$ib") | grep '^[<>]' | sed 's/^/    /'
      } >> "$impfile"
      if [ "$a" = "$b" ]; then
        impclean=$((impclean+1))
        printf '%s  %s -> %s\n' "${c:0:8}" "$old" "$new" >> "$purefile"
      fi
    fi
    if [ "$a" = "$b" ]; then
      clean=$((clean+1))
    else
      dirty=$((dirty+1))
      n=$(diff <(printf '%s' "$a") <(printf '%s' "$b") | grep -c '^[<>]')
      printf '%6s  %s  %s -> %s\n' "$n" "${c:0:8}" "$old" "$new"
    fi
  done < <(git diff -M --name-status "$c^" "$c" -- '*.go')

  # The R-status boundary: a move git did not pair at the default 50% similarity
  # never reaches the loop above at all. Detect again at 10% and report the gap.
  while IFS=$'\t' read -r status old new; do
    case "$status" in R*) ;; *) continue;; esac
    case "$old" in *.go) ;; *) continue;; esac
    grep -qxF "$(printf '%s\t%s' "$old" "$new")" "$pairfile" && continue
    printf '%s  %s -> %s  (%s)\n' "${c:0:8}" "$old" "$new" "$status" >> "$extrafile"
  done < <(git diff -M10% --name-status "$c^" "$c" -- '*.go')
done

echo
echo "moves seen: $moves   pure (identical after stripping): $clean   with residue: $dirty"

echo
echo "import sets changed on $impchanged of the $moves moves; $impclean of those are pure after"
echo "stripping, so the import delta is the only thing that changed and nothing else lists them:"
cat "$purefile"
echo
echo "every import delta, in full:"
cat "$impfile"

echo
extra=$(wc -l < "$extrafile" | tr -d ' ')
echo "renames the default threshold missed, found again at -M10%: $extra"
cat "$extrafile"
