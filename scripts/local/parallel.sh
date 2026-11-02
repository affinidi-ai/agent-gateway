#!/usr/bin/env bash
# Run groups of make targets side by side, for `make local`: each group's
# targets in order, in a make of its own, its output in <run>/<name>.log so
# the groups' lines never mix. Then one summary names each group with its
# time and the last lines of its log (the whole tail when it failed), adds it
# to <run>/summary.txt, and the script fails if any group did.
#
#   parallel.sh <title> <name>=<make args> [<name>=<make args> ...]
#
# A run's folder is tmp/local/<date>_<time>/, made by the outermost call and
# handed to every nested one (LOCAL_LOG_DIR), so one `make local` keeps all its
# logs together; tmp/local/latest points at the newest. The oldest folders past
# the last KEEP_RUNS (20) are removed as a run starts.
#
# PARALLEL=0 runs the groups one after another (less memory, same logs).
# ALLOW_FAIL names groups whose failure is only a warning (space-separated).
# Ctrl-C reaches every group: they share the terminal's process group.
set -u

title=${1:?usage: parallel.sh <title> <name>=<make args>...}
shift
make=${MAKE:-make}
root=tmp/local
# Nested: a group of an outer call runs this one, so its output goes to that
# group's log. Its header and summary are still said on the terminal (say).
nested=0
[ -n "${LOCAL_LOG_DIR:-}" ] && nested=1
if [ -z "${LOCAL_LOG_DIR:-}" ]; then
    LOCAL_LOG_DIR="$root/$(date +%Y-%m-%d_%H%M%S)"
    export LOCAL_LOG_DIR
    mkdir -p "$LOCAL_LOG_DIR"
    ln -sfn "$(basename "$LOCAL_LOG_DIR")" "$root/latest"
    # The oldest runs first (the names sort by time); the newest KEEP_RUNS stay.
    runs=("$root"/20??-??-??_??????)
    keep=${KEEP_RUNS:-20}
    for ((i = 0; i < ${#runs[@]} - keep; i++)); do
        rm -rf "${runs[i]}"
    done
fi
dir=$LOCAL_LOG_DIR
mkdir -p "$dir"

tty=0
[ "$nested" = 1 ] && { : >/dev/tty; } 2>/dev/null && tty=1
if [ -t 1 ] || [ "$tty" = 1 ]; then
    blue=$'\033[0;34m' green=$'\033[0;32m' yellow=$'\033[1;33m' red=$'\033[0;31m' dim=$'\033[2m' off=$'\033[0m'
else
    blue='' green='' yellow='' red='' dim='' off=''
fi

# A line the person should see as it happens: on stdout, and for a nested
# call also on the terminal (its stdout is a log, which gets it uncoloured).
say() {
    if [ "$nested" = 1 ]; then
        printf '%s\n' "$1" | sed $'s/\033\\[[0-9;]*m//g'
        [ "$tty" = 1 ] && printf '%s\n' "$1" 2>/dev/null >/dev/tty
    else
        printf '%s\n' "$1"
    fi
    return 0
}

# One group: its make, its log, then its exit status and seconds.
run() {
    local name=$1 start=$SECONDS
    shift
    "$make" --no-print-directory "$@" >"$dir/$name.log" 2>&1
    echo "$? $((SECONDS - start))" >"$dir/$name.status"
}

# The tree: each nesting level is indented one step under its parent, and a
# level's groups hang off it (├─ and └─ for the last).
depth=${LOCAL_DEPTH:-0}
export LOCAL_DEPTH=$((depth + 1))
pad=''
for ((i = 0; i < depth; i++)); do
    pad+="${dim}│${off}  "
done
branch() { # the glyph for item $1 of $2
    if [ "$1" -eq "$2" ]; then printf '└─'; else printf '├─'; fi
}

names=()
started=$SECONDS
say "${pad}${blue}▶ $title${off}"
n=0
for group in "$@"; do
    name=${group%%=*}
    args=${group#*=}
    names+=("$name")
    n=$((n + 1))
    rm -f "$dir/$name.status"
    say "${pad}${dim}$(branch "$n" "$#") $name: make $args  (log: $dir/$name.log)${off}"
    # shellcheck disable=SC2086 # a group's make arguments split on spaces
    if [ "${PARALLEL:-1}" = 0 ]; then
        run "$name" $args
    else
        run "$name" $args &
    fi
done
wait

failed=0
summary=()
n=0
for name in "${names[@]}"; do
    rc=1 secs=0
    [ -f "$dir/$name.status" ] && read -r rc secs <"$dir/$name.status"
    took="$((secs / 60))m $((secs % 60))s"
    n=$((n + 1))
    b=$(branch "$n" "${#names[@]}")
    echo
    if [ "$rc" = 0 ]; then
        echo "${dim}── $name ──${off}"
        tail -n 6 "$dir/$name.log"
        summary+=("${pad}${dim}$b${off} ${green}✅ $name ($took)${off}")
    elif [[ " ${ALLOW_FAIL:-} " == *" $name "* ]]; then
        echo "${yellow}── $name failed (allowed) ──${off}"
        tail -n 40 "$dir/$name.log"
        summary+=("${pad}${dim}$b${off} ${yellow}⚠️  $name ($took): failed, allowed - $dir/$name.log${off}")
    else
        echo "${red}── $name failed ──${off}"
        tail -n 80 "$dir/$name.log"
        summary+=("${pad}${dim}$b${off} ${red}❌ $name ($took) - $dir/$name.log${off}")
        failed=1
    fi
done
total=$((SECONDS - started))
echo
heading="${pad}${blue}■ $title, $((total / 60))m $((total % 60))s${off}"
say "$heading"
for line in "${summary[@]}"; do
    say "$line"
done
# The same summary, uncoloured, kept with the run's logs to compare runs.
printf '%s\n' "$heading" "${summary[@]}" | sed $'s/\033\\[[0-9;]*m//g' >>"$dir/summary.txt"
exit "$failed"
