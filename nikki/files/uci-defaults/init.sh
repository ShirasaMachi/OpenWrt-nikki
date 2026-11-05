#!/bin/sh

. "$IPKG_INSTROOT/etc/nikki/scripts/include.sh"

# Only initialize a fresh configuration; upgrades keep existing credentials.
init=$(uci -q get nikki.config.init)
[ "$init" = "1" ] || exit 0

# Generate 256 bits from the system CSPRNG, encoded for UCI and Mihomo.
generate_secret() {
	local value
	value=$(hexdump -v -n 32 -e '32/1 "%02x"' /dev/urandom) || return 1
	[ "${#value}" -eq 64 ] || return 1
	case "$value" in
		*[!0-9a-f]*) return 1 ;;
	esac
	printf '%s' "$value"
}

# Prepare both values before changing UCI. Do not replace preconfigured values,
# even when an image or an interrupted installation still has the init flag.
api_secret=$(uci -q get nikki.mixin.api_secret)
proxy_password=$(uci -q get 'nikki.@authentication[0].password')
new_api_secret=''
new_proxy_password=''
[ -n "$api_secret" ] || new_api_secret=$(generate_secret) || exit 1
[ -n "$proxy_password" ] || new_proxy_password=$(generate_secret) || exit 1

if [ -n "$new_api_secret" ]; then
	uci set nikki.mixin.api_secret="$new_api_secret" || exit 1
fi
if [ -n "$new_proxy_password" ]; then
	uci set "nikki.@authentication[0].password=$new_proxy_password" || exit 1
fi

# remove nikki.config.init
uci del nikki.config.init || exit 1

# commit
uci commit nikki || exit 1

# exit with 0
exit 0
