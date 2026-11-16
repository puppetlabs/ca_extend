#!/bin/bash

declare PT__installdir

# shellcheck disable=SC1090
source "$PT__installdir/ca_extend/files/common.sh"

PUPPET_BIN='/opt/puppetlabs/puppet/bin'
RUBY_BIN='/opt/puppetlabs/puppet/bin/ruby'

PUPPET_SERVER="$("$PUPPET_BIN/puppet" config print server)"

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
# Determine whether this is Puppet Enterprise or Puppet Core.
#
# Puppet Enterprise installs:
#   /opt/puppetlabs/server/pe_version
#
# Open source Puppet Core does not.
#
if [ ! -f /opt/puppetlabs/server/pe_version ]; then

  ca_storage_backend="filesystem"

else

  #
  # Determine whether the Puppet Enterprise CA is using the
  # database backend or the legacy filesystem backend.
  #
  classifier_data="$(
    curl -sS \
      --connect-timeout 20 \
      --max-time 180 \
      --fail \
      --cert "$($PUPPET_BIN/puppet config print hostcert)" \
      --key "$($PUPPET_BIN/puppet config print hostprivkey)" \
      --cacert "$($PUPPET_BIN/puppet config print localcacert)" \
      "https://${PUPPET_SERVER}:4433/classifier-api/v1/groups"
  )" || fail "Unable to query PE classifier API"

  #
  # Parse classifier response using Puppet Ruby.
  #
  # Avoid introducing a dependency on jq, which is not guaranteed
  # to be installed on all supported operating systems.
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
  )" || fail "Unable to parse PE classifier API response"

  #
  # Older PE releases do not define ca_storage_backend.
  #
  # When the parameter does not exist, the Classifier API
  # returns null. Treat this as filesystem in order to
  # maintain backwards compatibility.
  #
  if [ -z "$ca_storage_backend" ] || [ "$ca_storage_backend" = "null" ]; then
    ca_storage_backend="filesystem"
  fi

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
      "https://${PUPPET_SERVER}:8140/puppet-ca/v1/certificate_statuses/any?state=signed"
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
      cutoff = Time.at(ARGV[0].to_i)

      result = {
        "valid" => [],
        "expired" => []
      }

      JSON.parse(STDIN.read).each do |cert|
        next unless cert["name"]
        next unless cert["not_after"]

        expiry = Time.parse(cert["not_after"])

        filesystem_name = "#{cert["name"]}.pem"

        filesystem_date =
          expiry.utc.strftime("%b %e %H:%M:%S %Y GMT").gsub(/\s+/, " ").strip

        if expiry.to_i <= cutoff.to_i
          result["expired"] << {
            filesystem_name => filesystem_date
          }
        else
          result["valid"] << {
            filesystem_name => filesystem_date
          }
        end
      end

      puts JSON.generate(result)
    ' "$to_date_epoch" || fail "Unable to parse Puppet CA API response"

#
# FILESYSTEM CA
#
# This path is used for:
#
#   - Puppet Core
#   - Puppet Enterprise using filesystem CA
#   - Older PE releases where ca_storage_backend
#     is not explicitly configured
#
# Certificates are read directly from signeddir and
# OpenSSL is used to determine expiration dates.
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
  # dependencies. We as of now we don't include jq binaries in Bolt.
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
