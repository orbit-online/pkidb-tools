#!/usr/bin/env bash

pkidb_pam() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
  PATH=$("$pkgroot/.upkg/.bin/path_prepend" "$pkgroot/.upkg/.bin")
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/common.sh"

  DOC="pkidb-pam - Exclusively manage PAM CAs and download their CRLs
Usage:
  pkidb-pam FINGERPRINT...
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-pam.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:96}; usage=${DOC:63:33}; digest=f36cc; shorts=(); longs=()
argcounts=(); node_0(){ value FINGERPRINT a true; }; node_1(){ oneormore 0; }
node_2(){ required 1; }; node_3(){ required 2; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:63:33}" >&2; exit 1
}'; unset var_FINGERPRINT; parse 3 "$@"; local prefix=${DOCOPT_PREFIX:-''}
unset "${prefix}FINGERPRINT"
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-pam.sh`
  eval "$(docopt "$@")"
  check_all_deps
  [[ $EUID = 0 ]] || fatal "You must be root"

  local ret=0 fingerprint cert_path cert_link_path certs_path=/etc/pam_pkcs11/cacerts
  # Remove unspecified CAs
  while read -r -d $'\0' cert_path; do
    if ! fingerprint=$(generate_fingerprint <"$cert_path"); then
      warning "Unable to generate fingerprint for '%s'" "$cert_path"
      fingerprint='<UNKNOWN>'
    fi
    # shellcheck disable=2153
    if [[ ${FINGERPRINT[*]} =~ (^|[[:space:]])$fingerprint($|[[:space:]]) && $cert_path = "${certs_path}/${fingerprint}.pem" ]]; then
      verbose "Found specified CA with fingerprint '%s'" "$fingerprint"
    else
      info "Found unspecified or misnamed CA with fingerprint '%s'. Removing." "$fingerprint"
      while read -r -d $'\0' cert_link_path; do
        if [[ $cert_path = "$(realpath "$cert_link_path")" ]]; then
          rm -fv "$cert_link_path" | tee_warning
          break;
        fi
      done < <(find "$certs_path" -type l -print0)
      if [[ -z $cert_link_path ]]; then
        warning "Unable to find and remove subject hash link for certificate '%s'" "$fingerprint"
      fi
      rm -fv "$cert_path" | tee_warning
    fi
  done < <(find "$certs_path" -type f -print0)
  # Update specified CAs
  for fingerprint in "${FINGERPRINT[@]}"; do
    "$pkgroot/pkidb-ca.sh" --dest "${certs_path}/${fingerprint}.pem" "$fingerprint" || ret=$?
  done
  (cd "$certs_path" && pkcs11_make_hash_link) || ret=$?

  local crl_path crl_link_path crls_path=/etc/pam_pkcs11/crls
  # Remove unspecified CA CRLs
  while read -r -d $'\0' crl_path; do
    fingerprint=$(basename "$crl_path" .pem)
    if [[ ${FINGERPRINT[*]} =~ (^|[[:space:]])$fingerprint($|[[:space:]]) ]]; then
      verbose "Found specified CA CRL with fingerprint '%s'" "$fingerprint"
    else
      info "Found unspecified CA CRL with fingerprint '%s'. Removing." "$fingerprint"
      while read -r -d $'\0' crl_link_path; do
        if [[ $crl_path = "$(realpath "$crl_link_path")" ]]; then
          rm -fv "$crl_link_path" | tee_warning
          break;
        fi
      done < <(find "$crls_path" -type l -print0)
      if [[ -z $crl_link_path ]]; then
        warning "Unable to find and remove subject hash link for crl '%s'" "$fingerprint"
      fi
      rm -fv "$crl_path" | tee_warning
    fi
  done < <(find "$crls_path" -type f -print0)
  # Update CRLs for the specified CAs
  for fingerprint in "${FINGERPRINT[@]}"; do
    "$pkgroot/pkidb-crl.sh" --dest "${crls_path}/${fingerprint}.pem" "${certs_path}/${fingerprint}.pem" || ret=$?
  done
  (cd "$crls_path" && pkcs11_make_hash_link)

  info "The PAM PKCS#11 CA certificates and their CRLs have been updated"
  return $ret
}

pkidb_pam "$@"
