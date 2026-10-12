#!/bin/bash

declare PT__installdir

# shellcheck disable=SC1090
source "$PT__installdir/ca_extend/files/common.sh"

PUPPET_BIN='/opt/puppetlabs/puppet/bin'
RUBY_BIN='/opt/puppetlabs/puppet/bin/ruby'

to_date="${date:-+3 months}"
to_date_epoch="$(date --date="$to_date" +"%s")" || fail "Error calculating date"

# It's possible that we are not on a Puppet AIO system. If we cannot find an
# openssl binary in the AIO directory, we accept one in $PATH.
if [ -x "${PUPPET_BIN}/openssl" ]; then
  openssl="${PUPPET_BIN}/openssl"
else
  openssl="$(command -v openssl)" || fail "Unable to find openssl"
fi

#
# Determine whether the Puppet CA is using the database backend or the legacy filesystem backend.
#
classifier_data="$(
  curl -sS \
    --connect-timeout 20 \
    --max-time 180 \
    --fail \
    --cert "$($PUPPET_BIN/puppet config print hostcert)" \
    --key "$($PUPPET_BIN/puppet config print hostprivkey)" \
    --cacert "$($PUPPET_BIN/puppet config print localcacert)" \
    "https://$(hostname -f):4433/classifier-api/v1/groups"
)" || fail "Unable to query PE classifier API"

#
# Parse classifier response using Puppet Ruby.
#
ca_storage_backend="$(
  echo "$classifier_data" |
  "$RUBY_BIN" -rjson -e '
    data = JSON.parse(STDIN.read)

    group = data.find do |g|
      g["name"] == "PE Infrastructure"
    end

    backend = group&.dig(
      "classes",
      "puppet_enterprise",
      "ca_storage_backend"
    )

    puts backend
  '
)"

#
# Older versions return null because the parameter doesn't exist.
#
if [ -z "$ca_storage_backend" ] || [ "$ca_storage_backend" = "null" ]; then
  ca_storage_backend="filesystem"
fi

#
# DATABASE CA
#
if [ "$ca_storage_backend" = "database" ]; then

  #
  # Retrieve all signed certificates from the CA API.
  #
  certificate_statuses="$(
    curl -sS \
      --connect-timeout 30 \
      --max-time 600 \
      --fail \
      --cert "$($PUPPET_BIN/puppet config print hostcert)" \
      --key "$($PUPPET_BIN/puppet config print hostprivkey)" \
      --cacert "$($PUPPET_BIN/puppet config print localcacert)" \
      "https://$(hostname -f):8140/puppet-ca/v1/certificate_statuses/any?state=signed"
  )" || fail "Unable to retrieve signed certificates from Puppet CA API"

  #
  # Let Ruby handle:
  # - JSON parsing
  # - Date parsing
  # - Date comparison
  # - JSON generation
  #
  echo "$certificate_statuses" |
    "$RUBY_BIN" -rjson -rtime -e '
      require "json"
      require "time"

      cutoff = Time.at(ARGV[0].to_i)

      result = {
        "valid" => [],
        "expired" => []
      }

      JSON.parse(STDIN.read).each do |cert|
        next unless cert["name"]
        next unless cert["not_after"]

        expiry = Time.parse(cert["not_after"])

        if expiry.to_i <= cutoff.to_i
          result["expired"] << {
            cert["name"] => cert["not_after"]
          }
        else
          result["valid"] << {
            cert["name"] => cert["not_after"]
          }
        end
      end

      puts JSON.generate(result)
    ' "$to_date_epoch"

#
# FILESYSTEM CA
#
elif [ "$ca_storage_backend" = "filesystem" ]; then

  valid=()
  expired=()

  shopt -s nullglob

  signeddir="$("$PUPPET_BIN/puppet" config print signeddir)" ||
    fail "Unable to determine Puppet signed certificate directory"

  for cert in "$signeddir"/*; do

    [ -f "$cert" ] || continue

    # The -checkend command in openssl takes a number of seconds as an argument.
    # However, on older versions we may overflow a 32-bit integer if we use it.
    # Instead, convert both dates to epoch time and use bash arithmetic.
    expiry_date="$("$openssl" x509 -enddate -noout -in "$cert")" ||
      fail "Unable to read certificate: $cert"

    expiry_date="${expiry_date#*=}"

    expiry_seconds="$(date --date="$expiry_date" +"%s")" ||
      fail "Error calculating expiry date from enddate"

    # Only use the filename without preceding directories.
    short_cert="${cert##*/}"

    if (( to_date_epoch >= expiry_seconds )); then
      expired+=("\"$short_cert\"")
      expired+=("\"$expiry_date\"")
    else
      valid+=("\"$short_cert\"")
      valid+=("\"$expiry_date\"")
    fi

  done

  #
  # This is ugly, but we intentionally avoid introducing additional
  # dependencies. We as of now we don't include jq binaries in Bolt
  #
  valid_output=""
  expired_output=""

  if (( ${#valid[@]} > 0 )); then
    valid_output=$(printf '{%s: %s},' "${valid[@]}")
  fi

  if (( ${#expired[@]} > 0 )); then
    expired_output=$(printf '{%s: %s},' "${expired[@]}")
  fi

  # Create JSON arrays by stripping the trailing comma and adding brackets.
  echo "{\"valid\": [${valid_output%,}], \"expired\": [${expired_output%,}]}"

else
  fail "Unsupported Puppet CA storage backend: ${ca_storage_backend}"
fi
