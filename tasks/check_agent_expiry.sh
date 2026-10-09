#!/bin/bash

declare PT__installdir

# shellcheck disable=SC1090
source "$PT__installdir/ca_extend/files/common.sh"

PUPPET_BIN='/opt/puppetlabs/puppet/bin'

valid=()
expired=()

to_date="${date:-+3 months}"
to_date="$(date --date="$to_date" +"%s")" || fail "Error calculating date"

#
# Locate openssl
#
if [ -x "${PUPPET_BIN}/openssl" ]; then
  openssl="${PUPPET_BIN}/openssl"
else
  openssl="$(command -v openssl)" || fail "Unable to find openssl"
fi

#
# Determine CA backend from PE Infrastructure node group
#
classifier_data="$(
  curl -sS \
    --connect-timeout 60 \
    --max-time 300 \
    --fail \
    --cert "$($PUPPET_BIN/puppet config print hostcert)" \
    --key "$($PUPPET_BIN/puppet config print hostprivkey)" \
    --cacert "$($PUPPET_BIN/puppet config print localcacert)" \
    "https://$(hostname -f):4433/classifier-api/v1/groups"
)" || fail "Unable to query PE classifier API"

ca_storage_backend="$(
  echo "$classifier_data" |
  jq -r '
    .[]
    | select(.name=="PE Infrastructure")
    | .classes.puppet_enterprise.ca_storage_backend
  '
)"

#
# Older PE versions don't have the parameter.
# jq returns "null" in that case.
#
if [ -z "$ca_storage_backend" ] || [ "$ca_storage_backend" = "null" ]; then
  ca_storage_backend="filesystem"
fi

#
# DATABASE CA
#
if [ "$ca_storage_backend" = "database" ]; then

  certificate_statuses="$(
    curl -sS \
      --connect-timeout 300 \
      --max-time 900 \
      --fail \
      --cert "$($PUPPET_BIN/puppet config print hostcert)" \
      --key "$($PUPPET_BIN/puppet config print hostprivkey)" \
      --cacert "$($PUPPET_BIN/puppet config print localcacert)" \
      "https://$(hostname -f):8140/puppet-ca/v1/certificate_statuses/any?state=signed"
  )" || fail "Unable to retrieve signed certificates from Puppet CA API"

  tmpfile="$(mktemp)" ||
    fail "Unable to create temporary file"

  echo "$certificate_statuses" |
    jq -r '.[] | [.name, .not_after] | @tsv' > "$tmpfile"

  while IFS=$'\t' read -r short_cert expiry_date; do

    [ -z "$short_cert" ] && continue

    parsed_expiry_date="$(echo "$expiry_date" | sed -E 's/T/ /; s/UTC$/ UTC/')"

    expiry_seconds="$(
      date --date="$parsed_expiry_date" +"%s"
    )" || fail "Error calculating expiry date for certificate ${short_cert}"

    if (( to_date >= expiry_seconds )); then
      expired+=("\"$short_cert\"")
      expired+=("\"$expiry_date\"")
    else
      valid+=("\"$short_cert\"")
      valid+=("\"$expiry_date\"")
    fi

  done < "$tmpfile"

  rm -f "$tmpfile"

#
# FILESYSTEM CA
#
elif [ "$ca_storage_backend" = "filesystem" ]; then

  shopt -s nullglob

  signeddir="$("$PUPPET_BIN/puppet" config print signeddir)" ||
    fail "Unable to determine Puppet signed certificate directory"

  for cert in "$signeddir"/*; do

    [ -f "$cert" ] || continue

    expiry_date="$("$openssl" x509 -enddate -noout -in "$cert")" ||
      fail "Unable to read certificate: $cert"

    expiry_date="${expiry_date#*=}"

    expiry_seconds="$(date --date="$expiry_date" +"%s")" ||
      fail "Error calculating expiry date from enddate"

    short_cert="${cert##*/}"

    if (( to_date >= expiry_seconds )); then
      expired+=("\"$short_cert\"")
      expired+=("\"$expiry_date\"")
    else
      valid+=("\"$short_cert\"")
      valid+=("\"$expiry_date\"")
    fi

  done

else
  fail "Unsupported Puppet CA storage backend: ${ca_storage_backend}"
fi

#
# Build JSON output
#
valid_output=""
expired_output=""

if (( ${#valid[@]} > 0 )); then
  valid_output=$(printf '{%s: %s},' "${valid[@]}")
fi

if (( ${#expired[@]} > 0 )); then
  expired_output=$(printf '{%s: %s},' "${expired[@]}")
fi

echo "{\"valid\": [${valid_output%,}], \"expired\": [${expired_output%,}]}"
