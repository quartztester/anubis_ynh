#!/bin/bash

#=================================================
# COMMON VARIABLES AND CUSTOM HELPERS
#=================================================

# Local variables dedicated to the app go here

# Absolute path of the root helper installed by this package
APPLY_BIN="/usr/local/bin/anubis-ynh-apply"
SUDOERS_FILE="/etc/sudoers.d/$app"

# Run the root-owned apply helper (idempotent; regenerates fragments, env,
# reloads nginx). Safe to call from install/upgrade/restore/change_url/config.
run_apply() {
	ANUBIS_APP="$app" "$APPLY_BIN" "$@" || ynh_die "anubis-ynh-apply failed"
}
