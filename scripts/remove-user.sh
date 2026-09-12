#!/bin/sh
# remove-user.sh — teardown companion to add-user.sh (PLAN.md §17.8.6 / §17.8.7 item 4)
#
# Usage: remove-user.sh <email> [--purge-pass|--keep-pass] [--force] [--dry-run]
#
# Removes an Omnical user end-to-end (the inverse of add-user.sh):
#   1. calendar + addressbook collections  (DAV DELETE, hard — X-No-Trashbin: 1)
#   2. app tokens                          (principals app-token remove, all)
#   3. share subscriptions                 (subscriptions remove, all)
#   4. the principal                       (principals remove)
#   5. pass entries                        (behind --purge-pass, default ON,
#                                          after a backup note is written first)
#
# The principal id on the router is the RAW email (that is what `principals
# list` shows).  Pass-store keys appear in two layouts — the existing store
# uses secrets/omnical/<raw email>/<client>.gpg, while add-user.sh writes
# secrets/omnical/<underscored email>/app-token-<client>.gpg.  The script
# resolves the live principal id from the router (tries the email, then the
# underscored form) and backs-up/purges whichever pass layout exists.
#
# Idempotent: re-running with an already-removed principal skips the router
# teardown (pass purge still runs unless --keep-pass).
#
# The DAV collection deletes are deliberately HARD rather than trashbin soft:
# `calendars`/`addressbooks` FK `principals (id) ON DELETE RESTRICT`, and
# RustiCal soft deletes keep the row alive with deleted_at set — so a plain
# `principals remove` fails with "FOREIGN KEY constraint failed" while any
# collection row exists.  `X-No-Trashbin: 1` releases the FK; the principal
# row then goes away.  (RustiCal's own object tombstones cascade away with
# their collection; nothing is left orphaned.)
#
# Environment:
#   ROUTER_HOST          SSH target (default: router)
#   ROUTER_USER          SSH user (default: root)
#   RUSTICAL             rustical CLI path on the router (default: /usr/sbin/rustical)
#   PASS_DIR             pass store prefix (default: secrets/omnical)
#   OMNICAL_DAV_TOKEN    override the DAV-deletion token (default: the
#                        stored app-token-vdirsyncer for this id)
#   OMNICAL_DAV_URL      override the DAV base (default: http://127.0.0.1:4000)
set -eu

usage() {
    echo "usage: remove-user.sh <email> [--purge-pass|--keep-pass] [--force] [--dry-run]" >&2
}

if [ $# -lt 1 ]; then
    usage
    exit 1
fi
email="$1"
shift

purge_pass=1
force=0
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --purge-pass) purge_pass=1 ;;
        --keep-pass)  purge_pass=0 ;;
        --force)      force=1 ;;
        --dry-run)    dry_run=1 ;;
        *)            echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

ROUTER_HOST="${ROUTER_HOST:-router}"
ROUTER_USER="${ROUTER_USER:-root}"
RUSTICAL="${RUSTICAL:-/usr/sbin/rustical}"
PASS_DIR="${PASS_DIR:-secrets/omnical}"
DAV_URL="${OMNICAL_DAV_URL:-https://192.168.1.21:8443}"
DAV_INTERNAL_URL="${OMNICAL_DAV_INTERNAL_URL:-http://127.0.0.1:4000}"

# pass-side key uses the add-user.sh convention (email -> underscores)
id="$(echo "$email" | tr '@' '_')"

say()  { echo "==> $*"; }
warn() { echo "!! $*" >&2; }

# mutations: executed unless --dry-run (then printed only)
rc() {
    if [ "$dry_run" -eq 1 ]; then
        echo "SSH: $*" >&2
        return 0
    fi
    ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$@"
}

# read-only queries: always executed (they drive the dry-run plan too)
rcap() {
    ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$@"
}

# local command wrapper honoring --dry-run (pass ops run locally)
loc() {
    if [ "$dry_run" -eq 1 ]; then
        echo "LOCAL: $*" >&2
        return 0
    fi
    sh -c "$*"
}

dav_propfind() {
    # $1 = collection-home path; the whole command is ONE arg so ssh/remote
    # shell re-parse preserves the headers/URL quoting
    # -k: cert is for 0115d8cf.duckdns.org but we connect via IP (internal tooling)
    rcap "curl -s -k -u '$pid:$token' -X PROPFIND -H 'Depth: 1' '$DAV_URL$1'" || true
}

dav_delete() {
    # $1 = collection path; runs on the router via SSH (uses internal URL)
    if [ "$dry_run" -eq 1 ]; then
        echo "SSH: curl -s -f -u '$pid:<token>' -X DELETE -H 'X-No-Trashbin: 1' '$DAV_INTERNAL_URL$1'" >&2
        return 0
    fi
    rc "curl -s -f -u '$pid:$token' -X DELETE -H 'X-No-Trashbin: 1' '$DAV_INTERNAL_URL$1'"
}

echo "=== remove-user: $email (pass id=$id) ==="
echo "  router:   ${ROUTER_USER}@${ROUTER_HOST}"
echo "  purge-pass: $([ "$purge_pass" -eq 1 ] && echo yes || echo no)"
echo "  force:    $([ "$force" -eq 1 ] && echo yes || echo no)"
echo "  dry-run:  $([ "$dry_run" -eq 1 ] && echo yes || echo no)"
echo ""

# ---- 0) Resolve the principal id on the router --------------------------------
if ! principals="$(rcap "$RUSTICAL" principals list 2>/dev/null)"; then
    warn "could not list principals on ${ROUTER_USER}@${ROUTER_HOST} (SSH/CLI failure)"
    exit 1
fi
pid=""
for cand in "$email" "$id"; do
    if printf '%s\n' "$principals" | grep -Eq "^${cand} \("; then
        pid="$cand"
        break
    fi
done
if [ -z "$pid" ]; then
    say "principal for $email not present on router (already removed?) — skipping router teardown"
else
    say "principal id on router: $pid"
fi

# ---- 1) DAV collection teardown ----------------------------------------------
if [ -n "$pid" ]; then
    # a live app token is required to authenticate the collection deletes;
    # prefer the explicit override, else the stored token.  Two layouts exist
    # in the pass store: the add-user.sh convention (underscored id, key
    # app-token-vdirsyncer) and the real store (raw email, key vdirsyncer).
    token=""
    if [ -n "${OMNICAL_DAV_TOKEN:-}" ]; then
        token="$OMNICAL_DAV_TOKEN"
    else
        for cand in "$email" "$id"; do
            for key in app-token-vdirsyncer vdirsyncer; do
                if pass show "$PASS_DIR/$cand/$key" >/dev/null 2>&1; then
                    token="$(pass show "$PASS_DIR/$cand/$key")"
                    break 2
                fi
            done
        done
    fi
    case "$token" in
        *"'"*) warn "DAV token contains a single quote — cannot use it safely over SSH; set OMNICAL_DAV_TOKEN" >&2; token="" ;;
    esac

    if [ -n "$token" ]; then
        for kind in caldav carddav; do
            home="/${kind}/principal/${pid}/"
            hometrim="$(printf '%s' "$home" | sed -e 's#^/##' -e 's#/$##')"
            say "DAV: PROPFIND depth 1 $kind home ($home)"
            xml="$(dav_propfind "$home")"
            hrefs="$(printf '%s\n' "$xml" \
                | grep -o '<href>[^<]*</href>' \
                | sed -e 's#<[^>]*>##g' -e 's#^/##' -e 's#/$##' -e 's#%40#@#g' \
                | sort -u)"
            leftovers=0
            if [ -n "$hrefs" ]; then
                for href in $hrefs; do
                    case "$href" in
                        "$hometrim"|*"_birthdays_"*|*"/inbox"*)  continue ;;
                        *"/outbox"*)                    continue ;;
                        "${hometrim}/"*) : ;;           # a real child collection
                        *)                              continue ;;
                    esac
                    leftovers=$((leftovers + 1))
                    say "DAV: DELETE /$href"
                    dav_delete "/$href"
                done
            fi
            if [ "$leftovers" -eq 0 ]; then
                say "DAV: no collections under $kind home to delete"
            elif [ "$dry_run" -eq 0 ]; then
                # confirm nothing remains (soft tombstones would block the FK)
                remaining="$(printf '%s\n' "$(dav_propfind "$home")" \
                    | grep -o '<href>[^<]*</href>' \
                    | sed -e 's#<[^>]*>##g' -e 's#^/##' -e 's#/$##' -e 's#%40#@#g' \
                    | grep -v "_birthdays_" \
                    | grep -Fvx "$hometrim" || true)"
                if [ -n "$remaining" ]; then
                    warn "collections still listed under $home:"
                    printf '%s\n' "$remaining" | sed 's/^/    /' >&2
                fi
            fi
        done
    else
        warn "no DAV token available (set OMNICAL_DAV_TOKEN or store app-token-vdirsyncer in pass)."
        warn "Skipping collection deletes — 'principals remove' will fail below unless the "
        warn "principal has no collections (see the FK note in the header)."
    fi
fi

# ---- 2) revoke app tokens -----------------------------------------------------
if [ -n "$pid" ]; then
    say "revoking app tokens for $pid"
    tokens="$(rcap "$RUSTICAL" principals app-token list "$pid" 2>/dev/null || true)"
    n=0
    for tokid in $(printf '%s\n' "$tokens" | awk 'NF { print $1 }'); do
        n=$((n + 1))
        rc "$RUSTICAL" principals app-token remove "$pid" "$tokid"
    done
    [ "$n" -eq 0 ] && say "  (no app tokens)"
fi

# ---- 3) revoke subscriptions ---------------------------------------------------
if [ -n "$pid" ]; then
    say "revoking share subscriptions for $pid"
    subs="$(rcap "$RUSTICAL" subscriptions list "$pid" 2>/dev/null || true)"
    n=0
    for subid in $(printf '%s\n' "$subs" | awk 'NF { print $1 }'); do
        n=$((n + 1))
        rc "$RUSTICAL" subscriptions remove "$pid" "$subid"
    done
    [ "$n" -eq 0 ] && say "  (no subscriptions)"
fi

# ---- 4) remove the principal ---------------------------------------------------
if [ -n "$pid" ]; then
    say "removing principal $pid"
    if ! rc "$RUSTICAL" principals remove "$pid"; then
        if [ "$force" -eq 1 ]; then
            warn "principals remove failed (continuing per --force; principal may still exist)"
        else
            warn "principals remove failed — collections likely remain (no token was available)."
            warn "Re-run with OMNICAL_DAV_TOKEN set so the collections can be deleted."
            exit 1
        fi
    elif [ "$dry_run" -eq 0 ]; then
        remaining="$(rcap "$RUSTICAL" principals list 2>/dev/null || true)"
        if printf '%s\n' "$remaining" | grep -Eq "^${pid} \("; then
            warn "principal $pid still listed after removal!"
        fi
    fi
fi

# ---- 5) pass entries (local) --------------------------------------------------
# Purge whatever layout exists: add-user.sh writes secrets/omnical/<underscored id>,
# while the existing store uses secrets/omnical/<raw email>.
if [ "$purge_pass" -eq 1 ]; then
    pass_store="${PASSWORD_STORE_DIR:-$HOME/.password-store}"
    purged=0
    for cand in "$email" "$id"; do
        src="$pass_store/$PASS_DIR/$cand"
        [ -d "$src" ] || continue
        purged=1
        ts="$(date +%Y%m%d-%H%M%S)"
        bk="$HOME/backups/omnical/pass-removed/$cand-$ts"
        say "backing up pass entries to $bk (backup note)"
        if [ "$dry_run" -eq 1 ]; then
            echo "  [dry-run] mkdir -p '$bk' && cp -a '$src'/'.' '$bk'/" >&2
            echo "  [dry-run] write REMOVE-NOTE.txt into '$bk'" >&2
        else
            mkdir -p "$bk"
            cp -a "$src"/. "$bk"/
            {
                echo "Removed by remove-user.sh for $email ($(date -Iseconds))"
                echo "Pass dir: $PASS_DIR/$cand"
                echo "Contains entries:"
            } > "$bk/REMOVE-NOTE.txt"
            # note the gpg filenames (the plaintext secrets stay in pass until purge)
            find "$src" -type f -printf '%f\n' | sort | sed "s#^#$PASS_DIR/$cand/#" >> "$bk/REMOVE-NOTE.txt"
            say "backup note -> $bk/REMOVE-NOTE.txt"
        fi
        say "purging pass entries under $PASS_DIR/$cand"
        loc "pass rm -r -f '$PASS_DIR/$cand'"
    done
    [ "$purged" -eq 0 ] && say "no pass entries for $email — nothing to purge"
else
    say "keeping pass entries (--keep-pass)"
fi

echo ""
echo "=== done: $email ${pid:+teardown }complete ==="