#!/usr/bin/env bash

pkidb_sshd() {
  set -eo pipefail
  shopt -s inherit_errexit
  local pkgroot
  pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  PATH="$pkgroot/.upkg/.bin:$PATH"
  # shellcheck source=.upkg/orbit-online/records.sh/records.sh
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  # shellcheck source=common.sh
  source "$pkgroot/common.sh"

  DOC="pkidb-sshd - Manage client CAs for openssh-server and renew its hostkey
Usage:
  pkidb-sshd [-e -k TS...] -u URL -f FP FINGERPRINT...

Options:
  -u --step-url URL          URL to the step-ca
  -f --step-fp FP            Fingerprint of the step-ca root certificate
  -e --expiry-threshhold TS  Permitted remaining host certificate
                             lifetime before renewal [default: 336h]
  -k --key-algo ALGO         Host cert key algorithms to consider for renewal
                             [default: ecdsa ed25519 rsa]
"
# docopt parser below, refresh this parser with `docopt.sh update-sshd.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:535}; usage=${DOC:72:61}; digest=9a19a; shorts=(-e -u -f)
longs=(--expiry-threshhold --step-url --step-fp); argcounts=(1 1 1); node_0(){
value __expiry_threshhold 0; }; node_1(){ value __step_url 1; }; node_2(){
value __step_fp 2; }; node_3(){ value TS a true; }; node_4(){
value FINGERPRINT a true; }; node_5(){ oneormore 3; }; node_6(){ optional 0 5; }
node_7(){ oneormore 4; }; node_8(){ required 6 1 2 7; }; node_9(){ required 8; }
cat <<<' docopt_exit() { [[ -n $1 ]] && printf "%s\n" "$1" >&2
printf "%s\n" "${DOC:72:61}" >&2; exit 1; }'; unset var___expiry_threshhold \
var___step_url var___step_fp var_TS var_FINGERPRINT; parse 9 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__expiry_threshhold" \
"${prefix}__step_url" "${prefix}__step_fp" "${prefix}TS" "${prefix}FINGERPRINT"
eval "${prefix}"'__expiry_threshhold=${var___expiry_threshhold:-336h}'
eval "${prefix}"'__step_url=${var___step_url:-}'
eval "${prefix}"'__step_fp=${var___step_fp:-}'
if declare -p var_TS >/dev/null 2>&1; then eval "${prefix}"'TS=("${var_TS[@]}")'
else eval "${prefix}"'TS=()'; fi
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__expiry_threshhold" "${prefix}__step_url" \
"${prefix}__step_fp" "${prefix}TS" "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' update-sshd.sh`
  eval "$(docopt "$@")"
  check_all_deps
  [[ $EUID = 0 ]] || fatal "You must be root"

  local certs_path=/etc/ssh/client_ca_certs ca_keys_path=/etc/ssh/client_ca_keys \
    cert_paths=() key_lines=() \
    krl_path=/etc/ssh/revoked_client_keys.krl krlsig_path=/etc/ssh/revoked_client_keys.krl.sig
  [[ -d "$certs_path" ]] || mkdir "$certs_path"
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
      rm -fv "$cert_path" | tee_warning
    fi
  done < <(find "$certs_path" -type f -print0)
  # Update specified CAs
  for fingerprint in "${FINGERPRINT[@]}"; do
    "$pkgroot/fetch-ca.sh" --dest "${certs_path}/${fingerprint}.pem" "$fingerprint"
    cert_paths+=("${certs_path}/${fingerprint}.pem")
    key_lines+=("$(ssh-keygen -i -m PKCS8 -f <(get_pubkey <"${certs_path}/${fingerprint}.pem"))")
  done
  umask 133
  printf "%s\n" "${key_lines[@]}" >"$ca_keys_path"
  "$pkgroot/fetch-client-krl.sh" --dest "$krl_path" --sigdest "$krlsig_path" "${cert_paths[@]}"
  info "The client CA certs and the krl have been updated"

  export STEPPATH
  STEPPATH="$(mktemp -d)"
  # shellcheck disable=2154
  "$pkgroot/fetch-ca.sh" "$__step_fp" > "$STEPPATH/cas/$__step_fp.pem"
  # shellcheck disable=2064
  trap "rm -rf \"$STEPPATH\"" EXIT
  # shellcheck disable=2016,2154
  printf '{
  "ca-url": "%s",
  "root": "$STEPPATH/cas/%s.pem",
  "fingerprint": "%s",
  "redirect-url": ""
}
' "$__step_url" "$__step_fp" "$__step_fp"

  local algo ssh_host_key renewed=false
  # shellcheck disable=2154
  for algo in "${__key_algo[@]}"; do
    ssh_host_key="ssh_host_${algo}_key"
    if (cd /etc/ssh && step ssh needs-renewal --expires-in "$__expiry_threshhold" "${ssh_host_key}-cert.pub" 2>&1) | tee_verbose; then
      (cd /etc/ssh && step ssh renew --force "${ssh_host_key}-cert.pub" "$ssh_host_key")
      renewed=true
    fi
  done
  if $renewed; then
    info "The host keys have been renewed"
  else
    info "The host keys do not require renewal"
  fi

  systemctl reload ssh
}

pkidb_sshd "$@"
