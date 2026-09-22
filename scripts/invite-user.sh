#!/bin/sh
# invite-user.sh — send a one-time platform registration link (PLAN.md §17.8).
#
# A pure platform invite: the recipient registers with the invitation code and
# gets a full account (seeded personal collections via [registration]). NO
# group, NO shared calendar is attached — that surface stays separate
# (`rustical invites create --group`, or the portal Share section).
#
# Usage: invite-user.sh <email> [--expires YYYY-MM-DD|ISO8601] [--created-by NAME] [--dry-run]
#
# Environment:
#   ROUTER_HOST   SSH target (default: router)
#   ROUTER_USER   SSH user (default: root)
#   RUSTICAL      path to rustical binary on router (default: /usr/sbin/rustical)
set -eu

email="${1:?usage: invite-user.sh <email> [--expires …] [--created-by …] [--dry-run]}"
shift

expires=""
created_by="admin"
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --expires)   shift; expires="$1" ;;
        --created-by) shift; created_by="$1" ;;
        --dry-run)   dry_run=1 ;;
        *)           echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

ROUTER_HOST="${ROUTER_HOST:-router}"
ROUTER_USER="${ROUTER_USER:-root}"
RUSTICAL="${RUSTICAL:-/usr/sbin/rustical}"

echo "=== invite-user: $email ==="
echo "  router:    ${ROUTER_USER}@${ROUTER_HOST}"
echo "  expires:   ${expires:-<none>}"
echo "  created-by:$created_by"
echo "  dry-run:   $([ "$dry_run" -eq 1 ] && echo yes || echo no)"
echo ""

cmd="invites create --email '$email' --created-by '$created_by' --send"
if [ -n "$expires" ]; then
    cmd="$cmd --expires '$expires'"
fi

if [ "$dry_run" -eq 1 ]; then
    echo "ssh ${ROUTER_USER}@${ROUTER_HOST} -- \"$RUSTICAL\" $cmd" >&2
    echo "=== done (dry-run) ==="
    exit 0
fi

# The binary prints the invite code first, then confirms the send; the code alone
# stays usable if the mail ever bounces (admin can paste it into a /register form).
ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$RUSTICAL" $cmd
echo "=== done ==="