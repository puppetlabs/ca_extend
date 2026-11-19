#!/bin/bash

# Puppet CA extension script
#
# This script uses the Puppet CA certificates and private
# keys to generate new CA certificates that expire 15 years from
# now (same subject, key, serial and notBefore). A certificate that
# already expires no earlier than that is kept as it is.
#
# This script operates on 2-certificate CA bundles used by
# Puppet 6 and later in addition to single-certificate
# bundles used by Puppet 5 and earlier.
#
# This script requires that the default locations for
# the Puppet cadir and files underneath it are in use.
#
# Externally issued CA certificates are not supported.

set -e

PUPPET_BIN='/opt/puppetlabs/puppet/bin'

# Re-issues a CA certificate with a later notAfter (or keeps it unchanged if it already expires no
# earlier), keeping every extension (pathlen included) but the AKI, which is rebuilt from the issuer. Runs with the Ruby that ships with Puppet.
extend_cert="$(dirname "${BASH_SOURCE[0]}")/extend_cert.rb"

ca_bundle=$("${PUPPET_BIN}/puppet" config print --section master cacert)
ca_dir=$(dirname "${ca_bundle}")

printf 'CA bundle file: %s\n' "${ca_bundle}" >&2

printf '\n Checking CA bundle length...\n' >&2
chain_length=$(grep -cF 'BEGIN CERTIFICATE' "${ca_bundle}")

if (( chain_length > 2 )); then
  printf '%s certificates were found in: %s\n' "${chain_length}" "${ca_bundle}" >&2
  printf 'This script only works on CA bundles that contain one or two certificates.\n' >&2
  exit 1
elif (( chain_length == 2 )); then
  printf '2 entry Puppet CA detected in: %s\n' "${ca_bundle}" >&2
  root_key="${ca_dir}/root_key.pem"
  intermediate_key="${ca_dir}/ca_key.pem"

  [[ -r "${root_key}" ]] || {
    printf 'ERROR: The Root CA key file is not readable: %s\n' "${root_key}" >&2
    printf 'This script must be run as root and does not support externally issued CA certs.\n' >&2
    exit 1
  }

  [[ -r "${intermediate_key}" ]] || {
    printf 'ERROR: The Intermediate CA key file is not readable: %s\n' "${root_key}" >&2
    exit 1
  }
elif (( chain_length == 1 )); then
  printf '1 entry Puppet CA detected in: %s\n' "${ca_bundle}" >&2
  root_key="${ca_dir}/ca_key.pem"

  [[ -r "${root_key}" ]] || {
    printf 'ERROR: The Root CA key file is not readable: %s\n' "${root_key}" >&2
    printf 'This script must be run as root and does not support externally issued CA certs.\n' >&2
    exit 1
  }
else
  printf 'ERROR: No certificates detected in: %s\n' "${ca_bundle}" >&2
  exit 1
fi


# Build a temporary directory to hold the individual certificates and the renewed ones.

workdir=$(mktemp -d -t puppet_ca_extend.XXX)
printf 'Using working directory: %s\n' "${workdir}" >&2

# Separate CA bundle out into individual certificates
csplit -szf "${workdir}/puppet-ca-cert-" "${ca_bundle}" '/-----BEGIN CERTIFICATE-----/' '{*}'
ca_certs=("${workdir}"/puppet-ca-cert-*)


# Match keys up with certificates
root_cert=''

root_fingerprint=$("${PUPPET_BIN}/openssl" rsa -in "${root_key}" -noout -modulus|cut -d= -f2-)
for ca_cert in "${ca_certs[@]}"; do
  ca_fingerprint=$("${PUPPET_BIN}/openssl" x509 -in "${ca_cert}" -noout -modulus|cut -d= -f2-)
  if [[ "${ca_fingerprint}" == "${root_fingerprint}" ]]; then
    root_cert="${ca_cert}"
    break
  fi
done

[[ -n "${root_cert}" ]] || {
  printf 'ERROR: Could not find a certificate matching key %s\n' "${root_key}" >&2
  printf 'Checked: %s\n\t%s\n' "${ca_certs[@]}" >&2

  exit 1
}

if (( chain_length == 2 )); then
  intermediate_cert=''

  intermediate_fingerprint=$("${PUPPET_BIN}/openssl" rsa -in "${intermediate_key}" -noout -modulus|cut -d= -f2-)
  for ca_cert in "${ca_certs[@]}"; do
    ca_fingerprint=$("${PUPPET_BIN}/openssl" x509 -in "${ca_cert}" -noout -modulus|cut -d= -f2-)
    if [[ "${ca_fingerprint}" == "${intermediate_fingerprint}" ]]; then
      intermediate_cert="${ca_cert}"
      break
    fi
  done

  [[ -n "${intermediate_cert}" ]] || {
    printf 'ERROR: Could not find a certificate matching key %s\n' "${intermediate_key}" >&2
    printf 'Checked: %s\n\t%s\n' "${ca_certs[@]}" >&2

    exit 1
  }
fi


# Extend CA certs

# Compute the end date for new certificates. The renewed certificates keep the
# notBefore of the ones they replace.
# `end_date` only names the new bundle file. The helper is given the ISO 8601 form,
# because a two-digit year of 50 or more would be read as 19YY.
end_date=$(date -u --date='+15 years' '+%y%m%d%H%M%SZ')
end_date_iso=$(date -u --date='+15 years' '+%Y-%m-%dT%H:%M:%SZ')

root_subject=$("${PUPPET_BIN}/openssl" x509 -in "${root_cert}" -noout -subject|cut -d= -f2-)
root_issuer=$("${PUPPET_BIN}/openssl" x509 -in "${root_cert}" -noout -issuer|cut -d= -f2-)
root_enddate=$("${PUPPET_BIN}/openssl" x509 -in "${root_cert}" -noout -enddate|cut -d= -f2-)
root_serial_num=$("${PUPPET_BIN}/openssl" x509 -in "${root_cert}" -noout -serial|cut -d= -f2-)

[[ "${root_subject}" = "${root_issuer}" ]] || {
  printf 'ERROR: Root CA cert is not self-signed: %s\n' "${root_cert}" >&2
  printf 'Subject: %s\n' "${root_subject}" >&2
  printf 'Issuer: %s\n' "${root_issuer}" >&2
  printf 'This script does not support externally-issued CAs.' >&2

  exit 1
}

printf '\nExtending: %s\n' "${root_cert}" >&2
printf 'Subject: %s\n' "${root_subject}" >&2
printf 'Issuer: %s\n' "${root_issuer}" >&2
printf 'Serial: %s\n' "${root_serial_num}" >&2
printf 'End-Date: %s\n' "${root_enddate}" >&2

# Re-issue the root: same subject, key, serial and extensions (the AKI is rebuilt), a later notAfter.
# A root that already expires no earlier than the new end date is kept as it is (--keep-if-sufficient), so
# that it does not block renewing the intermediate.
"${PUPPET_BIN}/ruby" "${extend_cert}" \
  --cert "${root_cert}" \
  --key "${root_key}" \
  --not-after "${end_date_iso}" \
  --keep-if-sufficient \
  --out "${workdir}/root_ca.renewed.pem" >&2

if (( chain_length == 2 )); then
  intermediate_subject=$("${PUPPET_BIN}/openssl" x509 -in "${intermediate_cert}" -noout -subject|cut -d= -f2-)
  intermediate_issuer=$("${PUPPET_BIN}/openssl" x509 -in "${intermediate_cert}" -noout -issuer|cut -d= -f2-)
  intermediate_enddate=$("${PUPPET_BIN}/openssl" x509 -in "${intermediate_cert}" -noout -enddate|cut -d= -f2-)
  intermediate_serial_num=$("${PUPPET_BIN}/openssl" x509 -in "${intermediate_cert}" -noout -serial|cut -d= -f2-)

  [[ "${intermediate_issuer}" == "${root_issuer}" ]] || {
    printf 'ERROR: Intermediate CA cert is not issued by Root CA: %s\n' "${intermediate_cert}" >&2
    printf 'Subject: %s\n' "${intermediate_subject}" >&2
    printf 'Issuer: %s\n' "${intermediate_issuer}" >&2
    printf 'This script does not support externally-issued CAs.' >&2

    exit 1
  }

  printf '\nExtending: %s\n' "${intermediate_cert}" >&2
  printf 'Subject: %s\n' "${intermediate_subject}" >&2
  printf 'Issuer: %s\n' "${intermediate_issuer}" >&2
  printf 'Serial: %s\n' "${intermediate_serial_num}" >&2
  printf 'End-Date: %s\n' "${intermediate_enddate}" >&2

  # Re-issue the intermediate under the renewed root, signed with the root key (kept as it is if
  # it already expires no earlier than the new end date; it is then not capped to the root's expiry)
  "${PUPPET_BIN}/ruby" "${extend_cert}" \
    --cert "${intermediate_cert}" \
    --issuer-cert "${workdir}/root_ca.renewed.pem" \
    --key "${root_key}" \
    --not-after "${end_date_iso}" \
    --keep-if-sufficient \
    --out "${workdir}/intermediate_ca.renewed.pem" >&2
fi


# Generate output bundle
new_ca_bundle="${ca_dir}/ca_crt-expires-${end_date}.pem"

if (( chain_length == 2 )); then
  cat "${workdir}/intermediate_ca.renewed.pem" \
      "${workdir}/root_ca.renewed.pem" > "${new_ca_bundle}"
else
  cat "${workdir}/root_ca.renewed.pem" > "${new_ca_bundle}"
fi

printf '\nRenewed CA certificates.\n' >&2
printf '%s\n' "${new_ca_bundle}"
