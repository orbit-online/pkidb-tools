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
  pkidb-sshd --step-ca-url=URL --step-root-fp=FP FINGERPRINT...
"
# docopt parser below, refresh this parser with `docopt.sh update-sshd.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:142}; usage=${DOC:72:70}; digest=60d90; shorts=('' '')
longs=(--step-ca-url --step-root-fp); argcounts=(1 1); node_0(){
value __step_ca_url 0; }; node_1(){ value __step_root_fp 1; }; node_2(){
value FINGERPRINT a true; }; node_3(){ oneormore 2; }; node_4(){ required 0 1 3
}; node_5(){ required 4; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:72:70}" >&2; exit 1
}'; unset var___step_ca_url var___step_root_fp var_FINGERPRINT; parse 5 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__step_ca_url" \
"${prefix}__step_root_fp" "${prefix}FINGERPRINT"
eval "${prefix}"'__step_ca_url=${var___step_ca_url:-}'
eval "${prefix}"'__step_root_fp=${var___step_root_fp:-}'
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__step_ca_url" "${prefix}__step_root_fp" \
"${prefix}FINGERPRINT"; done; }
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
  "$pkgroot/fetch-ca.sh" "$__step_root_fp" > "$STEPPATH/cas/$__step_root_fp.pem"
  # shellcheck disable=2064
  trap "rm -rf \"$STEPPATH\"" EXIT
  # shellcheck disable=2016,2154
  printf '{
  "ca-url": "%s",
  "root": "$STEPPATH/cas/%s.pem",
  "fingerprint": "%s",
  "redirect-url": ""
}
' "$__step_ca_url" "$__step_root_fp" "$__step_root_fp"

  local ssh_host_keys=(ssh_host_ecdsa_key ssh_host_ed25519_key ssh_host_rsa_key) ssh_host_key renewed=false
  for ssh_host_key in "${ssh_host_keys[@]}"; do
    if (cd /etc/ssh && step ssh needs-renewal --expires-in 48h "${ssh_host_key}-cert.pub" 2>&1) | tee_verbose; then
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
