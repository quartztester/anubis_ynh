#!/bin/bash

#=================================================
# COMMON VARIABLES AND CUSTOM HELPERS
#=================================================

APPLY_BIN="/usr/local/bin/anubis-ynh-apply"
SUDOERS_FILE="/etc/sudoers.d/$app"

# Idempotent: regenerates fragments + env and reloads nginx; safe to call from any script.
run_apply() {
	ANUBIS_APP="$app" "$APPLY_BIN" "$@" || ynh_die "anubis-ynh-apply failed"
}
