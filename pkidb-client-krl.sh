#!/usr/bin/env bash

pkidb_client_krl() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
  PATH=$("$pkgroot/.upkg/.bin/path_prepend" "$pkgroot/.upkg/.bin")
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/common.sh"

  DOC="pkidb-client-krl - Retrieve a CMS signed KRL and verify it against CAs
Usage:
  pkidb-client-krl --dest=KRLPATH KRLNAME CAFILE...
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-client-krl.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:129}; usage=${DOC:71:58}; digest=67a0d; shorts=('')
longs=(--dest); argcounts=(1); node_0(){ value __dest 0; }; node_1(){
value KRLNAME a; }; node_2(){ value CAFILE a true; }; node_3(){ oneormore 2; }
node_4(){ required 0 1 3; }; node_5(){ required 4; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:71:58}" >&2; exit 1
}'; unset var___dest var_KRLNAME var_CAFILE; parse 5 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__dest" "${prefix}KRLNAME" \
"${prefix}CAFILE"; eval "${prefix}"'__dest=${var___dest:-}'
eval "${prefix}"'KRLNAME=${var_KRLNAME:-}'
if declare -p var_CAFILE >/dev/null 2>&1; then
eval "${prefix}"'CAFILE=("${var_CAFILE[@]}")'; else eval "${prefix}"'CAFILE=()'
fi; local docopt_i=1; [[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2
for ((;docopt_i>0;docopt_i--)); do declare -p "${prefix}__dest" \
"${prefix}KRLNAME" "${prefix}CAFILE"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-client-krl.sh`
  eval "$(docopt "$@")"
  check_all_deps

  # The KRL and its signature are in binary, encode in base64 during handling to
  # ensure bash doesn't mess with or fail because of it
  # e.g. "warning: command substitution: ignored null byte in input"

  # shellcheck disable=2154
  local pem pem_dest=${__dest}.pem
  # shellcheck disable=2153
  if [[ -e $__dest ]] && ! check_krl "${CAPATH[@]}" <"$pem_dest"; then
    info 'Current KRL invalid, deleting'
    rm -fv "$__dest" | tee_warning
  fi

  local url chg=0
  # shellcheck disable=2154
  url=$(get_krl_url "$KRLNAME")
  # shellcheck disable=2154
  has_changed "$url" "$pem_dest" || chg=$?

  if [[ $chg = 0 ]]; then
    pem=$(download "$url") || fatal $? "Unable to fetch the KRL '%s'" "$KRLNAME"
    krlb64=$(check_krlcms "${CAFILE[@]}" <<<"$pem")
    verbose "Saving KRL to '%s'" "$__dest"
    base64 -d <<<"$krlb64" >"$__dest"
    info "The KRL '%s' has been updated" "$KRLNAME"
    return 0
  elif [[ $chg = 3 ]]; then
    info "The KRL '%s' is up-to-date" "$KRLNAME"
    return 0
  else
    fatal $chg "Unable to fetch the KRL" "$KRLNAME"
  fi
}

check_krlcms() {
  local capaths=("$@") out ret
  debug 'Verifying the KRL using CAs at %s' "$(join_by , "${capaths[@]}")"
  if out=$(openssl cms -verify -inform PEM -CAfile <(cat ../../pkidb/ykpiv/cas/*.pem) -certfile <(cat "${capaths[@]}") -binary | base64); then
    verbose 'The KRL is valid'
  else
    ret=$?
    error 'Unable to verify the KRL CMS signature with CAs at %s. Error was: %s' "$(join_by , "${capaths[@]}")" "$out"
    return $ret
  fi
}

pkidb_client_krl "$@"
