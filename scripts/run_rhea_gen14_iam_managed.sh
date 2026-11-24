#!/usr/bin/env bash
# Recover the fixed disposable Rhea IAM users using unchanged managed policies.
set -euo pipefail
umask 077

fail() { printf 'rhea-gen14-iam-managed: REFUSED: %s\n' "$1" >&2; exit 2; }
[[ "$#" == 1 ]] || fail 'usage: bash run_rhea_gen14_iam_managed.sh {status|inspect|recover|verify}'
case "$1" in status|inspect|recover|verify) readonly MODE="$1" ;; *) fail 'unsupported mode' ;; esac
[[ "$(/usr/bin/id -u)" == 0 ]] || fail 'root required'
[[ ! -L "${BASH_SOURCE[0]}" ]] || fail 'linked launcher'
readonly BASE="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ancestor="$BASE"
while :; do
    [[ "$(/usr/bin/stat -c %u -- "$ancestor")" == 0 ]] || fail 'unsafe source ancestor owner'
    bits="$(/usr/bin/stat -c %a -- "$ancestor")"
    (( (8#$bits & 8#022) == 0 )) || fail 'writable source ancestor'
    [[ "$ancestor" != / ]] || break
    ancestor="$(/usr/bin/dirname -- "$ancestor")"
done
[[ "$(/usr/bin/stat -c %a -- "$BASE")" == 700 ]] || fail 'source directory must be 0700'

check() {
    local name="$1" expected="$2" file="$BASE/$1" actual
    [[ -f "$file" && ! -L "$file" ]] || fail "invalid source: $name"
    [[ "$(/usr/bin/stat -c %u -- "$file")" == 0 ]] || fail "wrong source owner: $name"
    [[ "$(/usr/bin/stat -c %h -- "$file")" == 1 ]] || fail "hardlinked source: $name"
    [[ "$(/usr/bin/stat -c %a -- "$file")" == 600 ]] || fail "source must be 0600: $name"
    if [[ -n "$expected" ]]; then
        actual="$(/usr/bin/sha256sum -- "$file")"
        [[ "${actual:0:64}" == "$expected" ]] || fail "source hash mismatch: $name"
    fi
}
check 'run_rhea_gen14_iam_managed.sh' ''
check 'rhea_gen14_create_iam_credentials.py' 'adeec619b4747d6e21fbe245a16fe55eba4a107305ec9750e16be50d6ccfe421'
check 'rhea_gen14_iam_admin_acceptance.py' 'ae7299650e6d350112379440a882b15f31748a9402a8192f4e29baa74400a20b'
check 'rhea_multi_sst_marker_iam.py' '6e0b941185ac49de1f60a36f98ca5ed3122720c9c59fc39320a86e750bf44c0a'
check 'rhea_multi_sst_signed_admission.py' '604970652d468d65008dc0b0b10367f6e8007de2f3fc2807b9b47f3e82e23574'
check 'rhea_gen14_recover_iam_policy.py' 'd3060848c0af10a931fbd3521458547e5c93d96cee0c4fd731300ae0232d0002'
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -E -s -B \
    "$BASE/rhea_gen14_recover_iam_policy.py" "$MODE"
