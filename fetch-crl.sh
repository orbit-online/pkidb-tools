#!/usr/bin/env bash

pkidb_fetch_crl() {
  set -eo pipefail
  shopt -s inherit_errexit
  local pkgroot
  pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  # shellcheck source=.upkg/orbit-online/records.sh/records.sh
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  # shellcheck source=common.sh
  source "$pkgroot/common.sh"

  DOC="pkidb-crl - Retrieve the CRL for a CA certificate and verify it
Usage:
  pkidb-crl --dest=CRLPATH CAPATH
"
# docopt parser below, refresh this parser with `docopt.sh fetch-crl.sh`
# shellcheck disable=2016,1090,1091,2034
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:104}; usage=${DOC:64:40}; digest=c7a08; shorts=('')
longs=(--dest); argcounts=(1); node_0(){ value __dest 0; }; node_1(){
value CAPATH a; }; node_2(){ required 0 1; }; node_3(){ required 2; }
cat <<<' docopt_exit() { [[ -n $1 ]] && printf "%s\n" "$1" >&2
printf "%s\n" "${DOC:64:40}" >&2; exit 1; }'; unset var___dest var_CAPATH
parse 3 "$@"; local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__dest" \
"${prefix}CAPATH"; eval "${prefix}"'__dest=${var___dest:-}'
eval "${prefix}"'CAPATH=${var_CAPATH:-}'; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__dest" "${prefix}CAPATH"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' fetch-crl.sh`
  eval "$(docopt "$@")"
  check_all_deps

  # shellcheck disable=2154
  if [[ -e $__dest ]] && ! check_crl "$CAPATH" <"$__dest"; then
    info 'Current CRL invalid, deleting'
    rm -fv "$__dest" | tee_warning
  fi

  local fingerprint url pem chg=0
  fingerprint=$(generate_fingerprint <"$CAPATH")
  url=$(get_crl_url "$fingerprint")
  # shellcheck disable=2154
  has_changed "$url" "$__dest" || chg=$?
  if [[ $chg = 0 ]]; then
    pem=$(download "$url") || fatal $? "Unable to fetch CRL for CA '%s'" "$fingerprint"
    check_crl "$CAPATH" <<<"$pem"
    verbose "Saving CRL to '%s'" "$__dest"
    printf -- "%s\n" "$pem" >"$__dest"
    info 'The CRL for the CA '%s' has been updated' "$fingerprint"
    return 0
  elif [[ $chg = 3 ]]; then
    info 'The CRL for the CA '%s' is up-to-date' "$fingerprint"
    return 0
  else
    fatal $chg "Unable to fetch CRL for CA '%s'" "$fingerprint"
  fi
}

check_crl() {
  local ca_path=$1 out ret
  debug 'Verifying the CRL using CA at "%s"' "$ca_path"
  if out=$(openssl crl -verify -CAfile "$ca_path" -noout 2>&1); then
    verbose 'The CRL is valid'
  else
    ret=$?
    error 'Unable to verify CRL signature with CA at "%s". Error was: %s' "$ca_path" "$out"
    return $ret
  fi
}

pkidb_fetch_crl "$@"
