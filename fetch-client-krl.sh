#!/usr/bin/env bash

fetch_client_krl() {
  set -eo pipefail
  shopt -s inherit_errexit
  local pkgroot
  pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  # shellcheck source=.upkg/orbit-online/records.sh/records.sh
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  # shellcheck source=common.sh
  source "$pkgroot/common.sh"

  DOC="pkidb-client-krl - Retrieve the KRL and signature as Base64, verify against CAs
Usage:
  pkidb-client-krl --dest=KRLPATH --sigdest=KRLSIGPATH CAPATH...
"
# docopt parser below, refresh this parser with `docopt.sh fetch-client-krl.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:151}; usage=${DOC:80:71}; digest=12065; shorts=('' '')
longs=(--dest --sigdest); argcounts=(1 1); node_0(){ value __dest 0; }
node_1(){ value __sigdest 1; }; node_2(){ value CAPATH a true; }; node_3(){
oneormore 2; }; node_4(){ required 0 1 3; }; node_5(){ required 4; }
cat <<<' docopt_exit() { [[ -n $1 ]] && printf "%s\n" "$1" >&2
printf "%s\n" "${DOC:80:71}" >&2; exit 1; }'; unset var___dest var___sigdest \
var_CAPATH; parse 5 "$@"; local prefix=${DOCOPT_PREFIX:-''}
unset "${prefix}__dest" "${prefix}__sigdest" "${prefix}CAPATH"
eval "${prefix}"'__dest=${var___dest:-}'
eval "${prefix}"'__sigdest=${var___sigdest:-}'
if declare -p var_CAPATH >/dev/null 2>&1; then
eval "${prefix}"'CAPATH=("${var_CAPATH[@]}")'; else eval "${prefix}"'CAPATH=()'
fi; local docopt_i=1; [[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2
for ((;docopt_i>0;docopt_i--)); do declare -p "${prefix}__dest" \
"${prefix}__sigdest" "${prefix}CAPATH"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' fetch-client-krl.sh`
  eval "$(docopt "$@")"
  check_all_deps

  # The KRL and its signature are in binary, encode in base64 during handling to
  # ensure bash doesn't mess with or fail because of it
  # e.g. "warning: command substitution: ignored null byte in input"

  local krl krlsig
  # shellcheck disable=2153,2154
  if [[ -e $__dest && -e $__sigdest ]]; then
    krl=$(base64 -w0 "$__dest")
    krlsig=$(base64 -w0 "$__sigdest")
    if ! check_krl "$krl" "$krlsig" "${CAPATH[@]}"; then
      info 'Current KRL invalid, deleting'
      rm -fv "$__dest" "$__sigdest" | tee_warning
      unset krl krlsig
    fi
  fi

  local krlurl krlsigurl krlchg=0 krlsigchg=0
  krlurl="$(get_krl_url)"
  krlsigurl="$(get_krlsig_url)"

  # shellcheck disable=2154
  has_changed "$krlurl" "$__dest" || krlchg=$?
  # shellcheck disable=2154
  has_changed "$krlsigurl" "$__sigdest" || krlsigchg=$?

  if [[ $krlchg = 3 && $krlsigchg = 3 ]]; then
    info 'The KRL is up-to-date'
    return 0
  fi

  if [[ $krlchg = 0 ]]; then
    krl=$(download "$krlurl" | base64 -w0) || fatal $? 'Unable to fetch KRL'
  else
    fatal $krlchg 'Unable to fetch KRL'
  fi
  if [[ $krlsigchg = 0 ]]; then
    krlsig=$(download "$krlsigurl" | base64 -w0) || fatal $? 'Unable to fetch KRL signature'
  else
    fatal $krlsigchg 'Unable to fetch KRL signature'
  fi

  # shellcheck disable=2153
  check_krl "$krl" "$krlsig" "${CAPATH[@]}"

  if [[ $krlchg = 0 ]]; then
    verbose "Saving KRL to '%s'" "$__dest"
    base64 -d <<<"$krl" >"$__dest"
  fi
  if [[ $krlsigchg = 0 ]]; then
    verbose "Saving KRL signature to '%s'" "$__sigdest"
    base64 -d <<<"$krlsig" >"$__sigdest"
  fi

  info 'The KRL has been updated'
  return 0
}

check_krl() {
  local krl=$1 krlsig=$2 out capath all_out
        shift; shift
  while [[ $# -gt 0 ]]; do
    capath=$1
    if out=$(openssl dgst -hex -sha256 -verify <(get_pubkey <"$capath") -signature <(base64 -d <<<"$krlsig") <(base64 -d <<<"$krl") 2>&1); then
      verbose 'The KRL is valid and was signed by the CA at "%s"' "$capath"
      return 0
    fi
    debug 'The CA at "%s" did not sign the KRL, trying next CA' "$capath"
    all_out="${all_out}\n${out}"
    shift
  done
  error 'Unable to verify KRL against any of the trusted CAs. Errors were:\n%s' "$all_out"
  return 1
}

fetch_client_krl "$@"
