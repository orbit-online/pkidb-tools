#!/usr/bin/env bash

main() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/.upkg/orbit-online/collections.sh/collections.sh"
  source "$pkgroot/common.sh"

  DOC="sign-dev-tls-cert - Retrieve a TLS cert for .local domains
Usage:
  sign-dev-tls-cert [-f -C DIR --san FQDN...] FQDN

Options:
  --san FQDN          Additional domains to add to the certificate
  -C --dir DIR        Directory to switch to before signing/renewing
  -f --force-renewal  Renew the certificate regardless of expiration time

Notes:
  The certificate bundle and key will be output to ./bundle.pem and ./key.pem
"
# docopt parser below, refresh this parser with `docopt.sh sign-dev-tls-cert.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:422}; usage=${DOC:59:57}; digest=77f05; shorts=(-f -C '')
longs=(--force-renewal --dir --san); argcounts=(0 1 1); node_0(){
switch __force_renewal 0; }; node_1(){ value __dir 1; }; node_2(){
value __san 2 true; }; node_3(){ value FQDN a; }; node_4(){ oneormore 2; }
node_5(){ optional 0 1 4; }; node_6(){ required 5 3; }; node_7(){ required 6; }
cat <<<' docopt_exit() { [[ -n $1 ]] && printf "%s\n" "$1" >&2
printf "%s\n" "${DOC:59:57}" >&2; exit 1; }'; unset var___force_renewal \
var___dir var___san var_FQDN; parse 7 "$@"; local prefix=${DOCOPT_PREFIX:-''}
unset "${prefix}__force_renewal" "${prefix}__dir" "${prefix}__san" \
"${prefix}FQDN"; eval "${prefix}"'__force_renewal=${var___force_renewal:-false}'
eval "${prefix}"'__dir=${var___dir:-}'
if declare -p var___san >/dev/null 2>&1; then
eval "${prefix}"'__san=("${var___san[@]}")'; else eval "${prefix}"'__san=()'; fi
eval "${prefix}"'FQDN=${var_FQDN:-}'; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__force_renewal" "${prefix}__dir" "${prefix}__san" \
"${prefix}FQDN"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' sign-dev-tls-cert.sh`
  eval "$(docopt "$@")"
  (
    [[ $FQDN = *.local ]] || fatal "The FQDN '%s' must be a .local domain" "$FQDN"
    contains_element "$FQDN" "${__san[@]}" || __san=("$FQDN" "${__san[@]}")
    [[ -z $__dir ]] || cd "$__dir"
    local domains_changed=false
    # shellcheck disable=2154
    if ! $__force_renewal && [[ -e bundle.pem ]]; then
      local requested_domains=("$FQDN" "${__san[@]}") cert cert_domains=()
      cert=$(sed '/END CERTIFICATE/q' bundle.pem)
      readarray -t cert_domains <<<"$(get_sans <<<"$cert")"
      cert_domains+=("$(get_subject_field '2.5.4.3' 'commonName' <<<"$cert")")
      if ! cmp --silent <(sort <(join_by $'\n' "${cert_domains[@]}")) <(sort <(join_by $'\n' "${requested_domains[@]}")); then
        domains_changed=true
      fi
    fi
    # shellcheck disable=2154
    if [[ ! -e key.pem || ! -e bundle.pem ]] || $domains_changed || $__force_renewal || \
      STEP_SKIP_P11_KIT=true pkidb-step certificate needs-renewal --expires-in=100% bundle.pem 2>&1 | LOGPROGRAM=step tee_info; then
      # Certificate does not exist or has expired, we must authenticate with a YubiKey
      export STEP_PIN_DESC="${FQDN} must be issued/renewed. To do that \`step\` needs to authenticate to step-ca with your YubiKey #%s"
      local domain san_opts=()
      for domain in "${__san[@]}"; do
        [[ $domain = *.local ]] || fatal "The SAN '%s' must be a .local domain" "$domain"
        san_opts+=(--san "$domain")
      done
      pkidb-step ca certificate "${san_opts[@]}" --force "$FQDN" bundle.pem key.pem
    elif STEP_SKIP_P11_KIT=true pkidb-step certificate needs-renewal --expires-in=50% bundle.pem 2>&1 | LOGPROGRAM=step tee_info; then
      # Certificate is still valid. Renew without having to ask for YubiKey access.
      STEP_SKIP_P11_KIT=true pkidb-step ca renew --force bundle.pem key.pem 2>&1 | LOGPROGRAM=step tee_info
    fi
  )
}

main "$@"
