#!/bin/sh
# add-user.sh — admin companion to create a user on the router (PLAN.md §17.8.6)
#
# Usage: add-user.sh <email> [--name "…"] [--group family]
#                       [--no-share] [--hub] [--force] [--dry-run]
#
# Environment:
#   ROUTER_HOST   SSH target (default: router)
#   ROUTER_USER   SSH user (default: root)
#   RUSTICAL      path to rustical binary on router (default: /usr/sbin/rustical)
#   PASS_DIR      pass store prefix (default: secrets/omnical)
set -eu

email="${1:?usage: add-user.sh <email> [--name …] [--group family] [--no-share] [--hub] [--force] [--dry-run]}"
shift

name=""
group=""
no_share=0
hub=0
force=0
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --name)   shift; name="$1" ;;
        --group)  shift; group="$1" ;;
        --no-share) no_share=1 ;;
        --hub)    hub=1 ;;
        --force)  force=1 ;;
        --dry-run) dry_run=1 ;;
        *)        echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

ROUTER_HOST="${ROUTER_HOST:-router}"
ROUTER_USER="${ROUTER_USER:-root}"
RUSTICAL="${RUSTICAL:-/usr/sbin/rustical}"
PASS_DIR="${PASS_DIR:-secrets/omnical}"

if [ -z "$name" ]; then
    name="$email"
fi

id="$(echo "$email" | tr '@' '_')"

# Generate a random 32-char frontend password
frontend_pw="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)"

# Idempotency: refuse to clobber existing pass entry without --force
if [ "$dry_run" -eq 0 ] && [ "$force" -eq 0 ]; then
    if pass show "$PASS_DIR/$email/frontend" >/dev/null 2>&1; then
        echo "ERROR: pass entry $PASS_DIR/$email/frontend already exists (use --force to overwrite)" >&2
        exit 1
    fi
fi

run() {
    if [ "$dry_run" -eq 1 ]; then
        echo "SSH: $*" >&2
    else
        ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$@"
    fi
}

put_pass() {
    local key="$1" ; shift
    local val="$1"
    if [ "$dry_run" -eq 1 ]; then
        echo "pass: $PASS_DIR/$email/$key = <redacted>" >&2
    else
        printf '%s\n' "$val" | pass insert -e -f "$PASS_DIR/$email/$key"
    fi
}

echo "=== add-user: $email (id=$id) ==="
echo "  router: ${ROUTER_USER}@${ROUTER_HOST}"
echo "  name:   $name"
echo "  group:  ${group:-<none>}"
echo "  share:  $([ "$no_share" -eq 1 ] && echo no || echo yes)"
echo "  hub:    $([ "$hub" -eq 1 ] && echo yes || echo no)"
echo "  force:  $([ "$force" -eq 1 ] && echo yes || echo no)"
echo "  dry-run:$([ "$dry_run" -eq 1 ] && echo yes || echo no)"
echo ""

# 1) Create principal (piped password)
echo "-- principals create --"
if [ "$dry_run" -eq 1 ]; then
    echo "ssh $ROUTER_USER@$ROUTER_HOST 'echo \"$frontend_pw\" | $RUSTICAL principals create --name \"$name\" $email --password'" >&2
else
    ssh "${ROUTER_USER}@${ROUTER_HOST}" "echo '$frontend_pw' | $RUSTICAL principals create --name '$name' $email --password"
fi

# 2) Create app tokens per client
echo "-- app-token create (web, vdirsyncer) --"
for client in web vdirsyncer; do
    if [ "$dry_run" -eq 1 ]; then
        echo "app-token create --name $client $email" >&2
        token="<generated>"
    else
        token="$(ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$RUSTICAL" principals app-token create --name "$client" "$email")"
    fi
    put_pass "app-token-$client" "$token"
done
put_pass "frontend" "$frontend_pw"

# 3) Seed collections via HTTP MKCOL (§17.7 smoke bodies)
#    Server reachable via dav-tls; MKCOL runs on the router since the dev machine
#    may not be on the local LAN.
auth_basic() {
    # CalDAV Basic Auth requires an app token, not the frontend password
    local tok
    tok="$(pass show "$PASS_DIR/$email/app-token-web" 2>/dev/null)"
    printf '%s:%s' "$email" "$tok" | base64 -w0
}

mkcol() {
    local path="$1" ; shift
    local body="$1"
    local depth="${2:-0}"
    if [ "$dry_run" -eq 1 ]; then
        echo "MKCOL $path (depth=$depth)" >&2
    else
        local auth
        auth="$(auth_basic)"
        printf '%s\n' "$body" | ssh "${ROUTER_USER}@${ROUTER_HOST}" "cat > /tmp/.add-user-mkcol.xml && curl -sk -X MKCOL -H 'Authorization: Basic ${auth}' -H 'Content-Type: application/xml' --data-binary @/tmp/.add-user-mkcol.xml 'https://192.168.1.21:8443${path}' && rm -f /tmp/.add-user-mkcol.xml"
    fi
}

PERSONAL_CALENDAR='<?xml version="1.0" encoding="UTF-8"?>
<D:mkcol xmlns:D="DAV:">
  <D:set><D:prop>
    <D:resourcetype><D:collection/><C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/></D:resourcetype>
    <D:displayname>personal</D:displayname>
  </D:prop></D:set>
</D:mkcol>'

TASKS_CALENDAR='<?xml version="1.0" encoding="UTF-8"?>
<D:mkcol xmlns:D="DAV:">
  <D:set><D:prop>
    <D:resourcetype><D:collection/><C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/></D:resourcetype>
    <D:displayname>tasks</D:displayname>
  </D:prop></D:set>
</D:mkcol>'

PERSONAL_ADDRESSBOOK='<?xml version="1.0" encoding="UTF-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:set><D:prop>
    <D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>
    <D:displayname>personal</D:displayname>
  </D:prop></D:set>
</D:mkcol>'

echo "-- MKCOL personal/tasks calendars + personal addressbook --"
mkcol "/caldav/principal/${email}/personal" "$PERSONAL_CALENDAR"
mkcol "/caldav/principal/${email}/tasks" "$TASKS_CALENDAR"
mkcol "/carddav/principal/${email}/personal" "$PERSONAL_ADDRESSBOOK"

# 4) Personal share feed (unless --no-share)
if [ "$no_share" -eq 0 ]; then
    echo "-- subscriptions add personal --"
    if [ "$dry_run" -eq 1 ]; then
        echo "subscriptions add --kind calendar $email personal" >&2
    else
        ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$RUSTICAL" subscriptions add --kind calendar "$email" personal
    fi
fi

# 5) Optional group membership
if [ -n "$group" ]; then
    echo "-- membership assign $email -> $group --"
    if [ "$dry_run" -eq 1 ]; then
        echo "principals membership assign $email --to $group" >&2
    else
        ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$RUSTICAL" principals membership assign "$email" --to "$group"
    fi
fi

# 6) --hub: append Google/external account pair to vdirsyncer config
if [ "$hub" -eq 1 ]; then
    vdir_config="$HOME/.config/vdirsyncer/config"
    echo "-- vdirsyncer config: append $email pair --"
    if [ "$dry_run" -eq 1 ]; then
        echo "append pair config for $email to $vdir_config" >&2
    else
        mkdir -p "$(dirname "$vdir_config")"
        cat >> "$vdir_config" <<EOF
# Added by add-user.sh for $email ($(date -I))
[pair ${id}-google]
a = "${id}-google-remote"
b = "${id}-local"
collections = ["from a", "from b"]
conflicts = "a wins"
EOF
    fi
fi

# 7) Fast-start summary
echo ""
echo "=== fast-start summary for $email ==="
echo "  frontend URL:  https://${ROUTER_HOST}:8443/frontend/user/${email}"
echo "  frontend pw:   $frontend_pw"
echo "  app-token web:     $(pass show "$PASS_DIR/$email/app-token-web" 2>/dev/null || echo '<stored in pass>')"
echo "  app-token vdirsyncer: $(pass show "$PASS_DIR/$email/app-token-vdirsyncer" 2>/dev/null || echo '<stored in pass>')"
[ "$no_share" -eq 0 ] && echo "  personal feed: /frontend/user/${email}/share (revocable)"
[ -n "$group" ]      && echo "  group: $group"
echo "=== done ==="
