#!/usr/bin/env bash

pkidb_sshd() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  PATH="$pkgroot/.upkg/.bin:$PATH"
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/common.sh"

  DOC="pkidb-sshd - Manage client CAs for openssh-server and renew its hostkey
Usage:
  pkidb-sshd [options -k ALGO... --krl NAME...] FINGERPRINT...

Options:
  --krl NAME                 Name of a KRL to cache
  -f --step-root-fp FP       Fingerprint of the step-ca root certificate
                             [default: \$STEP_ROOT_FP]
  -e --expiry-threshhold TS  Permitted remaining host certificate lifetime
                             before renewal [default: 50%]
  -k --key-algo ALGO         Host cert key algorithms to consider for renewal
                             [default: ecdsa ed25519 rsa]
"
# docopt parser below, refresh this parser with `docopt.sh pkidb-sshd.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:600}; usage=${DOC:72:69}; digest=62732; shorts=(-f -e -k '')
longs=(--step-root-fp --expiry-threshhold --key-algo --krl); argcounts=(1 1 1 1)
node_0(){ value __step_root_fp 0; }; node_1(){ value __expiry_threshhold 1; }
node_2(){ value __key_algo 2 true; }; node_3(){ value __krl 3 true; }; node_4(){
value FINGERPRINT a true; }; node_5(){ optional 0 1; }; node_6(){ oneormore 2; }
node_7(){ oneormore 3; }; node_8(){ optional 5 6 7; }; node_9(){ oneormore 4; }
node_10(){ required 8 9; }; node_11(){ required 10; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:72:69}" >&2; exit 1
}'; unset var___step_root_fp var___expiry_threshhold var___key_algo var___krl \
var_FINGERPRINT; parse 11 "$@"; local prefix=${DOCOPT_PREFIX:-''}
unset "${prefix}__step_root_fp" "${prefix}__expiry_threshhold" \
"${prefix}__key_algo" "${prefix}__krl" "${prefix}FINGERPRINT"
eval "${prefix}"'__step_root_fp=${var___step_root_fp:-'"'"'$STEP_ROOT_FP'"'"'}'
eval "${prefix}"'__expiry_threshhold=${var___expiry_threshhold:-50%}'
if declare -p var___key_algo >/dev/null 2>&1; then
eval "${prefix}"'__key_algo=("${var___key_algo[@]}")'; else
eval "${prefix}"'__key_algo=(ecdsa ed25519 rsa)'; fi
if declare -p var___krl >/dev/null 2>&1; then
eval "${prefix}"'__krl=("${var___krl[@]}")'; else eval "${prefix}"'__krl=()'; fi
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__step_root_fp" "${prefix}__expiry_threshhold" \
"${prefix}__key_algo" "${prefix}__krl" "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' pkidb-sshd.sh`
  eval "$(docopt "$@")"
  check_all_deps
  [[ $EUID = 0 ]] || fatal "You must be root"

  local ret=0 certs_path=/etc/ssh/client_ca_certs ca_keys_path=/etc/ssh/client_ca_keys \
    cert_paths=() ssh_pubkey key_lines=()
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
    "$pkgroot/pkidb-ca.sh" --dest "${certs_path}/${fingerprint}.pem" "$fingerprint" || { ret=$?; continue; }
    cert_paths+=("${certs_path}/${fingerprint}.pem")
    ssh_pubkey=$(ssh-keygen -i -m PKCS8 -f <(get_pubkey <"${certs_path}/${fingerprint}.pem")) || { ret=$?; continue; }
    key_lines+=("$ssh_pubkey")
  done
  umask 133
  printf "%s\n" "${key_lines[@]}" >"$ca_keys_path"

  local krl_name krl_path
  while read -r -d $'\0' krl_path; do
    krl_name=$(basename "$krl_path" .pem)
    # shellcheck disable=2154
    if [[ ${__krl[*]} =~ (^|[[:space:]])$krl_name($|[[:space:]]) ]]; then
      verbose "Found specified KRL named '%s'" "$krl_name"
    else
      info "Found unspecified KRL named '%s'. Removing." "$krl_name"
      rm -fv "$krl_path" | tee_warning
      rm -fv "$krl_path.sig" | tee_warning
    fi
  done < <(find /etc/ssh/ -type f -name '*.krl' -print0)
  for krl_name in "${__krl[@]}"; do
    "$pkgroot/pkidb-krl.sh" --dest "/etc/ssh/$krl_name.krl" --sigdest "/etc/ssh/$krl_name.krl.sig" "${cert_paths[@]}" || ret=$?
  done
  info "The client CA certs and the KRLs have been updated"

  # shellcheck disable=2154
  if [[ $__step_root_fp != "\$STEP_ROOT_FP" ]]; then
    export STEP_ROOT_FP=$__step_root_fp
  elif [[ -z $STEP_ROOT_FP ]]; then
    fatal "\$STEP_ROOT_FP is not defined"
  fi
  export STEP_URL
  STEP_URL=$(LOGLEVEL=warning "$pkgroot/pkidb-ca.sh" "$STEP_ROOT_FP" | get_subject_field "2.5.4.87" url)

  local algo ssh_host_key renewed=false
  # shellcheck disable=2154
  for algo in "${__key_algo[@]}"; do
    ssh_host_key="ssh_host_${algo}_key"
    if (cd /etc/ssh && step ssh needs-renewal --expires-in "$__expiry_threshhold" "${ssh_host_key}-cert.pub" 2>&1) | tee_verbose; then
      if (cd /etc/ssh && step ssh renew --force "${ssh_host_key}-cert.pub" "$ssh_host_key"); then
        renewed=true
      else
        ret=$?
      fi
    fi
  done
  if $renewed; then
    info "The host keys have been renewed"
  else
    info "The host keys do not require renewal"
  fi

  systemctl reload ssh
  return $ret
}

pkidb_sshd "$@"
