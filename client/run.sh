#!/usr/bin/with-contenv bashio
# Home Assistant add-on run script

export SERVER_ADDR="$(bashio::config 'server_addr')"
export TOKEN="$(bashio::config 'token')"
export FINGERPRINT="$(bashio::config 'fingerprint')"
export TARGET_ADDR="$(bashio::config 'target_addr')"

bashio::log.info "Starting HA Cloud Tunnel client..."
bashio::log.info "Server address: ${SERVER_ADDR}"
bashio::log.info "Target address: ${TARGET_ADDR}"

exec /app/client
