#!/bin/bash

# COMMON VARIABLES AND CUSTOM HELPERS

APPLY_BIN="/usr/local/bin/anubis-ynh-apply"
SUDOERS_FILE="/etc/sudoers.d/$app"

# app-owned, no world bits (CI unsafe-perms gate); both units run as $app
_anubis_perms() {
    chown -R "$app:$app" "$install_dir"
    chmod -R "u=rwX,go=" "$install_dir"
    chmod 0700 "$install_dir/bin/anubis"
}

# Idempotent: regenerates fragments + env and reloads nginx; safe to call from any script.
run_apply() {
	ANUBIS_APP="$app" "$APPLY_BIN" "$@" || ynh_die "anubis-ynh-apply failed"
}
