#!/usr/bin/env bash

pkidb_crl() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
  PATH=$("$pkgroot/.upkg/.bin/path_prepend" "$pkgroot/.upkg/.bin")
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/.upkg/orbit-online/collections.sh/collections.sh"
  source "$pkgroot/common.sh"

  DOC="pkidb-crl - Retrieve a CRL and verify it against CAs
Usage:
  pkidb-crl --dest=CRLPATH CRLNAME CAFILE...
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-crl.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:104}; usage=${DOC:53:51}; digest=8e2d5; shorts=('')
longs=(--dest); argcounts=(1); node_0(){ value __dest 0; }; node_1(){
value CRLNAME a; }; node_2(){ value CAFILE a true; }; node_3(){ oneormore 2; }
node_4(){ required 0 1 3; }; node_5(){ required 4; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:53:51}" >&2; exit 1
}'; unset var___dest var_CRLNAME var_CAFILE; parse 5 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__dest" "${prefix}CRLNAME" \
"${prefix}CAFILE"; eval "${prefix}"'__dest=${var___dest:-}'
eval "${prefix}"'CRLNAME=${var_CRLNAME:-}'
if declare -p var_CAFILE >/dev/null 2>&1; then
eval "${prefix}"'CAFILE=("${var_CAFILE[@]}")'; else eval "${prefix}"'CAFILE=()'
fi; local docopt_i=1; [[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2
for ((;docopt_i>0;docopt_i--)); do declare -p "${prefix}__dest" \
"${prefix}CRLNAME" "${prefix}CAFILE"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-crl.sh`
  eval "$(docopt "$@")"
  check_all_deps

  # shellcheck disable=2153,2154
  if [[ -e $__dest ]] && ! check_crl "${CAFILE[@]}" <"$__dest"; then
    info 'Current CRL invalid, deleting'
    rm -fv "$__dest" | tee_warning
  fi

  local url pem chg=0
  # shellcheck disable=2154
  url=$(get_crl_url "$CRLNAME")
  # shellcheck disable=2154
  has_changed "$url" "$__dest" || chg=$?
  if [[ $chg = 0 ]]; then
    pem=$(download "$url") || fatal $? "Unable to fetch the CRL '%s'" "$CRLNAME"
    check_crl "${CAFILE[@]}" <<<"$pem"
    verbose "Saving CRL to '%s'" "$__dest"
    printf -- "%s\n" "$pem" >"$__dest"
    info 'The CRL '%s' has been updated' "$CRLNAME"
    return 0
  elif [[ $chg = 3 ]]; then
    info 'The CRL '%s' is up-to-date' "$CRLNAME"
    return 0
  else
    fatal $chg "Unable to fetch the CRL '%s'" "$CRLNAME"
  fi
}

check_crl() {
  local capaths=("$@") out ret
  debug 'Verifying the CRL using CAs at %s' "$(join_by , "${capaths[@]}")"
  if out=$(openssl crl -verify -CAfile <(cat "${capaths[@]}") -noout 2>&1) && grep -q 'verify OK' <<<"$out"; then
    verbose 'The CRL is valid'
  else
    ret=$?
    error 'Unable to verify CRL signature with CAs at %s. Error was: %s' "$(join_by , "${capaths[@]}")" "$out"
    return $ret
  fi
}

pkidb_crl "$@"
