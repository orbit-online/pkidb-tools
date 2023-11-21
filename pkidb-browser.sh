#!/usr/bin/env bash

pkidb_browser() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  PATH="$pkgroot/.upkg/.bin:$PATH"
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/common.sh"

  DOC="pkidb-browser - Exclusively manage Browser CAs
Usage:
  pkidb-browser FINGERPRINT...
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-browser.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:84}; usage=${DOC:47:37}; digest=a0056; shorts=(); longs=()
argcounts=(); node_0(){ value FINGERPRINT a true; }; node_1(){ oneormore 0; }
node_2(){ required 1; }; node_3(){ required 2; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:47:37}" >&2; exit 1
}'; unset var_FINGERPRINT; parse 3 "$@"; local prefix=${DOCOPT_PREFIX:-''}
unset "${prefix}FINGERPRINT"
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-browser.sh`
  eval "$(docopt "$@")"
  check_all_deps

  if [ $EUID = 0 ]; then
    fatal "You must not be root"
  fi

  local fingerprint nickname trust existing_fingerprints=() tmp_ca_path changed=false
  local line line_matched=false nssdbpath="sql:$HOME/.pki/nssdb" expected_trust=CT,c,c
  # Remove unspecified CAs
  while read -r -d $'\n' line; do
  if [[ $line =~ ^(.+[^ ])\ +([pPcCTu,]+)\ *$ ]]; then
      nickname=${BASH_REMATCH[1]}
      trust=${BASH_REMATCH[2]}
      debug "Parsed line. Nickname: '%s'. Trust: '%s'" "$nickname" "$trust"
      line_matched=true
    elif $line_matched; then
      fatal "Unable to parse output line from 'certutil -L': %s" "$line"
    else
      debug "Header line not parsed, skipping: %s" "$line"
      continue
    fi
    fingerprint=$(get_fingerprint "$nssdbpath" "$nickname")
    # shellcheck disable=2153
    if [[ ${FINGERPRINT[*]} =~ (^|[[:space:]])$fingerprint($|[[:space:]]) ]]; then
      verbose "Found specified CA with fingerprint '%s'" "$fingerprint"
      if [[ $nickname != "$fingerprint" ]]; then
        info "Renaming CA '%s' to correct nickname" "$fingerprint"
        certutil -d "$nssdbpath" --rename -n "$nickname" --new-n "$fingerprint" -t "$expected_trust" 2> >(LOGPROGRAM=certutil tee_verbose)
        nickname=$fingerprint
        changed=true
      fi
      if [[ $trust != "$expected_trust" ]]; then
        info "Adjusting trust settings on CA '%s' to '%s'" "$fingerprint" "$expected_trust"
        certutil -d "$nssdbpath" -M -n "$nickname" -t "$expected_trust" 2> >(LOGPROGRAM=certutil tee_verbose)
      fi
      existing_fingerprints+=("$fingerprint")
    else
      info "Found unspecified CA with fingerprint '%s'. Removing." "$fingerprint"
      certutil -d "$nssdbpath" -D -n "$nickname" 2> >(LOGPROGRAM=certutil tee_verbose)
    fi
  done < <(certutil -d "$nssdbpath" -L 2> >(LOGPROGRAM=certutil tee_verbose))
  # Update specified CAs
  for fingerprint in "${FINGERPRINT[@]}"; do
    if [[ ! ${existing_fingerprints[*]} =~ (^|[[:space:]])$fingerprint($|[[:space:]]) ]]; then
      info "Adding CA '%s' to the DB" "$fingerprint"
      tmp_ca_path=$(mktemp)
      # shellcheck disable=2064
      trap "rm '$tmp_ca_path'" EXIT
      "$pkgroot/pkidb-ca.sh" "$fingerprint" > "$tmp_ca_path"
      certutil -d "$nssdbpath" -A -n "$fingerprint" -t "$expected_trust" -i "$tmp_ca_path" 2> >(LOGPROGRAM=certutil tee_verbose)
      changed=true
      rm "$tmp_ca_path"
      trap '' EXIT
    fi
  done

  if $changed; then
    info "The browser CA certificates have been updated"
  else
    info "The browser CA certificates are up-to-date"
  fi
}

get_fingerprint() {
  local nssdbpath=$1 nickname=$2 fingerprint
  fingerprint=$(certutil -d "$nssdbpath" -L -n "$nickname" 2> >(LOGPROGRAM=certutil tee_verbose) | grep -A1 'Fingerprint (SHA-256):' | tail -n+2 | sed 's/ *\|://g')
  if [[ -z $fingerprint ]]; then
    error "Unable to retrieve fingerprint from certutil DB for nickname '%s'" "$nickname"
    return 1
  fi
  printf -- "%s\n" "$fingerprint"
}

pkidb_browser "$@"
