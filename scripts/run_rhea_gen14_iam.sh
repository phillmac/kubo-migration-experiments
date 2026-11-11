#!/usr/bin/env bash
# Rhea gen14 Wasabi IAM acceptance wrapper.
# No production rclone credential import, shell sourcing, or IAM execution path.
set -euo pipefail
umask 077

readonly TOOL='rhea-gen14-iam-wrapper-v1'
if [[ "$#" -ne 1 ]]; then
    printf 'Usage: %s {status|plan|provision|accept|cleanup|lockout}\n' "$0" >&2
    exit 64
fi
case "$1" in
    status|plan|provision|accept|cleanup|lockout) readonly MODE="$1" ;;
    *) printf '%s: unsupported command\n' "$TOOL" >&2; exit 64 ;;
esac

# Only the bundled root-reviewed code can run. Refuse symlinks, unexpected
# ownership, writable ancestor, hardlinks and any modified source bytes.
readonly BASE="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly OWNER="$(/usr/bin/id -u)"
readonly ADMIN_SHA='ae7299650e6d350112379440a882b15f31748a9402a8192f4e29baa74400a20b'
readonly IAM_SHA='6e0b941185ac49de1f60a36f98ca5ed3122720c9c59fc39320a86e750bf44c0a'
readonly SIGNED_SHA='604970652d468d65008dc0b0b10367f6e8007de2f3fc2807b9b47f3e82e23574'

fail() { printf '%s: REFUSED: %s\n' "$TOOL" "$1" >&2; exit 2; }
[[ ! -L "$BASE" && -d "$BASE" ]] || fail 'source directory is a link/missing'
[[ "$(/usr/bin/stat -c %u -- "$BASE")" == "$OWNER" ]] || fail 'directory owner mismatch'
mode="$(/usr/bin/stat -c %a -- "$BASE")"
[[ "$mode" == '700' || "$mode" == '750' ]] || fail 'unsafe source directory mode'

check() {
    local name="$1" expected="$2" file="$BASE/$1" actual
    [[ -f "$file" && ! -L "$file" ]] || fail "invalid source: $name"
    [[ "$(/usr/bin/stat -c %u -- "$file")" == "$OWNER" ]] || fail "wrong owner: $name"
    [[ "$(/usr/bin/stat -c %h -- "$file")" == 1 ]] || fail "hardlinked source: $name"
    local perms
    perms="$(/usr/bin/stat -c %a -- "$file")"
    [[ "$perms" == 600 || "$perms" == 640 ]] || fail "unsafe mode: $name"
    actual="$(/usr/bin/sha256sum -- "$file")"
    [[ "${actual:0:64}" == "$expected" ]] || fail "source hash mismatch: $name"
}
check 'rhea_gen14_iam_admin_acceptance.py' "$ADMIN_SHA"
check 'rhea_multi_sst_marker_iam.py' "$IAM_SHA"
check 'rhea_multi_sst_signed_admission.py' "$SIGNED_SHA"

# Python entrypoint supports only plan/status. Every mutating mode refuses.
# Deliberately no credential/env inheritance or production rclone config access.
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -E -s -B \
    "$BASE/rhea_gen14_iam_admin_acceptance.py" "$MODE"
