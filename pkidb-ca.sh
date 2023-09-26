#!/usr/bin/env bash

pkidb_ca() {
  set -eo pipefail
  shopt -s inherit_errexit
  local pkgroot
  pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  PATH="$pkgroot/.upkg/.bin:$PATH"
  # shellcheck source=.upkg/orbit-online/records.sh/records.sh
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  # shellcheck source=common.sh
  source "$pkgroot/common.sh"

  DOC="pkidb-ca - Retrieve a CA certificate using the SHA-256 fingerprint
Usage:
  pkidb-ca [--dest=CAPATH] FINGERPRINT
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-ca.sh`
# shellcheck disable=2016,1090,1091,2034
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:112}; usage=${DOC:67:45}; digest=ca1f7; shorts=('')
longs=(--dest); argcounts=(1); node_0(){ value __dest 0; }; node_1(){
value FINGERPRINT a; }; node_2(){ optional 0; }; node_3(){ required 2 1; }
node_4(){ required 3; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:67:45}" >&2; exit 1
}'; unset var___dest var_FINGERPRINT; parse 4 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__dest" \
"${prefix}FINGERPRINT"; eval "${prefix}"'__dest=${var___dest:-}'
eval "${prefix}"'FINGERPRINT=${var_FINGERPRINT:-}'; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__dest" "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-ca.sh`
  eval "$(docopt "$@")"
  check_all_deps

  # shellcheck disable=2154
  if [[ -n $__dest && -e $__dest ]]; then
    # shellcheck disable=2153
    if check_fingerprint "$FINGERPRINT" <"$__dest" && check_expiration <"$__dest"; then
      info 'The CA '%s' exists and is valid' "$FINGERPRINT"
      return 0
    else
      info "CA '%s' invalid, deleting" "$FINGERPRINT"
      rm -fv "$__dest" | tee_warning
      return 1
    fi
  else
    local pem
    # shellcheck disable=2153
    pem=$(download "$(get_ca_url "$FINGERPRINT")") || fatal $? "Unable to fetch CA '%s'" "$FINGERPRINT"
    if check_fingerprint "$FINGERPRINT" <<<"$pem" && check_expiration <<<"$pem"; then
      if [[ -n $__dest ]]; then
        verbose "Saving CA '%s' to '%s'" "$FINGERPRINT" "$__dest"
        printf -- "%s\n" "$pem" >"$__dest"
      else
        verbose "No destination specified, outputting CA '%s'" "$FINGERPRINT"
        printf -- "%s\n" "$pem"
      fi
      info 'The CA '%s' has been downloaded and validated' "$FINGERPRINT"
      return 0
    else
      return 1
    fi
  fi
}

check_fingerprint() {
  local expected_fingerprint=$1 actual_fingerprint
  check_fp_format "$expected_fingerprint"
  actual_fingerprint=$(generate_fingerprint)
  if [[ $actual_fingerprint != "$expected_fingerprint" ]]; then
    error "The fingerprint of the certificate does match what was expected ('%s' vs. '%s')" "$actual_fingerprint" "$actual_fingerprint"
    return 1
  else
    verbose "The expected fingerprint matches the one from the certificate: '%s'" "$actual_fingerprint"
    return 0
  fi
}

check_expiration() {
  openssl x509 -checkend 0 2>&1 | LOGPROGRAM=openssl tee_verbose
}

pkidb_ca "$@"
