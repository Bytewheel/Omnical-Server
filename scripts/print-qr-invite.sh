#!/bin/sh
# print-qr-invite.sh — print a paper welcome sheet with a scannable registration
# link (PLAN.md §17.8): no email invite needed, recipients just scan and register.
#
# The script mints one invite on the router (same as `invite-user.sh` minus the
# --send mail), wraps its /register URL in a QR code, and composes a one-page
# letter-size PNG with contact info plus a second QR for the Matrix support
# space. The page is sent straight to the Brother printer.
#
# Usage: print-qr-invite.sh [--email ADDR] [--expires YYYY-MM-DD|ISO8601]
#                           [--created-by NAME] [--keep] [--dry-run]
#
# Environment:
#   ROUTER_HOST      SSH target (default: router)
#   ROUTER_USER      SSH user (default: root)
#   RUSTICAL         path to rustical binary on router (default: /usr/sbin/rustical)
#   PUBLIC_URL       base URL for /register links
#                    (default: https://0115d8cf.duckdns.org:8443)
#   MATRIX_SPACE_URL matrix.to URL of the support space
#                    (default: Omnical/HawkBook Alpha space invite)
#   PRINTER          lpr destination (default: brother-mfc-j985dw)
set -eu

email=""
expires=""
created_by="admin"
keep=0
dry_run=0

usage() {
    echo "usage: $(basename "$0") [--email ADDR] [--expires …] [--created-by …] [--keep] [--dry-run]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --email)      shift; [ $# -gt 0 ] || usage; email="$1" ;;
        --expires)    shift; [ $# -gt 0 ] || usage; expires="$1" ;;
        --created-by) shift; [ $# -gt 0 ] || usage; created_by="$1" ;;
        --keep)       keep=1 ;;
        --dry-run)    dry_run=1 ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done

ROUTER_HOST="${ROUTER_HOST:-router}"
ROUTER_USER="${ROUTER_USER:-root}"
RUSTICAL="${RUSTICAL:-/usr/sbin/rustical}"
PUBLIC_URL="${PUBLIC_URL:-https://0115d8cf.duckdns.org:8443}"
MATRIX_SPACE_URL="${MATRIX_SPACE_URL:-https://matrix.to/#/!SGnsUKLQfBVKwpbIfP:0115d8cf.duckdns.org?via=0115d8cf.duckdns.org}"
PRINTER="${PRINTER:-brother-mfc-j985dw}"

for tool in qrencode magick; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool not found in PATH" >&2; exit 1; }
done

echo "=== print-qr-invite ==="
echo "  router:    ${ROUTER_USER}@${ROUTER_HOST}"
echo "  email:     ${email:-<anyone>}"
echo "  expires:   ${expires:-<none>}"
echo "  created-by:$created_by"
echo "  public url:$PUBLIC_URL"
echo "  matrix:    $MATRIX_SPACE_URL"
echo "  printer:   $PRINTER"
echo "  dry-run:   $([ "$dry_run" -eq 1 ] && echo yes || echo no)"
echo ""

# 1) Mint the invite and build the register link from the printed code.
cmd="invites create --created-by '$created_by'"
[ -n "$email" ] && cmd="$cmd --email '$email'"
[ -n "$expires" ] && cmd="$cmd --expires '$expires'"

if [ "$dry_run" -eq 1 ]; then
    code="dryruncode42"
    echo "ssh ${ROUTER_USER}@${ROUTER_HOST} -- \"$RUSTICAL\" $cmd" >&2
else
    # The binary prints the invite code (last line of stdout); keep the code
    # usable even though this path sends no mail.
    output="$(ssh "${ROUTER_USER}@${ROUTER_HOST}" -- "$RUSTICAL" $cmd)"
    code="$(printf '%s\n' "$output" | sed -n '${s/[[:space:]]*$//;p;}')"
fi

register_url="${PUBLIC_URL%/}/register?code=${code}"

echo "  code:      $code"
echo "  register:  $register_url"
echo ""

# 2) Compose the page: QR codes + fixed text, assembled at 300 dpi letter size.
#
# Text is rendered with -pointsize + label: (not pango:, whose wrap metrics do
# not scale with -density); every line break is explicit here. Metrics were
# measured against URW/Nimbus fonts — the layout below fills a 2550x3300 page
# without rescaling.
tmp="$(mktemp -d)" || exit 1
trap 'rm -rf "$tmp"' EXIT

if [ "$keep" -eq 1 ]; then
    trap - EXIT
fi

# -s 15: 33-module register QR -> 555px, 37-module matrix QR -> 615px at 300 dpi.
qrencode -s 15 -m 2 -o "$tmp/qr-register.png" "$register_url"
qrencode -s 15 -m 2 -o "$tmp/qr-matrix.png" "$MATRIX_SPACE_URL"

W=2550
H=3300
REG_FONT="NimbusSans-Regular"
HEAD_FONT="URW-Gothic-Demi"

P1='You are invited to the
Omnical closed beta!
Thank you for your
participation.'

P2='When/if you need help, please
feel free to contact me by email,
Signal, or Matrix.
Contact info is below:'

INFO='burningserenity@novo-ordo.com
+1-407-670-4302 (Signal)
Matrix below:'

text_block() {
    # $1 = out path, $2 = pointsize, $3 = font, $4 = multi-line text
    local out="$1" pts="$2" font="$3" text="$4"
    magick -density 300 -background white -fill black \
        -font "$font" -pointsize "$pts" "label:${text}" "$out"
}

center() {
    # $1 = in path — extend to full page width, content centered
    local in="$1"
    local height
    height="$(magick -ping -format '%h' "$in" info:)"
    magick "$in" -background white -gravity center -extent "${W}x${height}" "$in"
}

text_block "$tmp/h.png" 68 "$HEAD_FONT" 'Omnical'
text_block "$tmp/p1.png" 34 "$REG_FONT" "$P1"
text_block "$tmp/p2.png" 34 "$REG_FONT" "$P2"
text_block "$tmp/info.png" 34 "$REG_FONT" "$INFO"

for f in "$tmp/h.png" "$tmp/p1.png" "$tmp/qr-register.png" \
         "$tmp/p2.png" "$tmp/info.png" "$tmp/qr-matrix.png"; do
    center "$f"
done

magick -size "${W}x40" xc:white "$tmp/gap.png"

magick \
    "$tmp/h.png" \
    "$tmp/gap.png" \
    "$tmp/p1.png" \
    "$tmp/gap.png" \
    "$tmp/qr-register.png" \
    "$tmp/gap.png" \
    "$tmp/p2.png" \
    "$tmp/gap.png" \
    "$tmp/info.png" \
    "$tmp/gap.png" \
    "$tmp/qr-matrix.png" \
    -append \
    "$tmp/stacked.png"

# Letter page, top/bottom margins balanced. The resize is a guard that only
# shrinks if the content grows (font substitutions can add a few percent); the
# measured stack is ~3334px so it currently scales by ~1.6%, keeping both QR
# codes comfortably scannable.
magick "$tmp/stacked.png" -resize "${W}x$((H - 20))>" \
    -background white -gravity center -extent "${W}x${H}" \
    "$tmp/omnical-invite.png"

# 3) Print.
if [ "$dry_run" -eq 1 ]; then
    echo "lpr -P $PRINTER $tmp/omnical-invite.png" >&2
    echo "=== done (dry-run) ==="
    exit 0
fi

lpr -P "$PRINTER" "$tmp/omnical-invite.png"

if [ "$keep" -eq 1 ]; then
    echo "kept: $tmp/omnical-invite.png"
fi
echo "=== done ==="