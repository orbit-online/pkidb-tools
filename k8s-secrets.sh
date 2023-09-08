#!/usr/bin/env bash

main() {
  set -eo pipefail
  shopt -s inherit_errexit
  local pkgroot
  pkgroot=$(upkg root "${BASH_SOURCE[0]}")
  PATH="$pkgroot/.upkg/.bin:$PATH"
  # shellcheck source=.upkg/orbit-online/records.sh/records.sh
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  DOC="pkidb-k8s-secrets - Retrieve CAs via fingerprint and create k8s secrets from them
Usage:
  pkidb-k8s-secrets [--namespace=NS] FINGERPRINT...

Notes:
* Make sure to specify \$PKIDBURL
* The namespace can also be specified via \$POD_NAMESPACE
"
# docopt parser below, refresh this parser with `docopt.sh k8s-secrets.sh`
# shellcheck disable=2016,1090,1091,2034,2154
docopt() { source "$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh" '1.0.0' || {
ret=$?; printf -- "exit %d\n" "$ret"; exit "$ret"; }; set -e
trimmed_doc=${DOC:0:238}; usage=${DOC:82:58}; digest=8eced; shorts=('')
longs=(--namespace); argcounts=(1); node_0(){ value __namespace 0; }; node_1(){
value FINGERPRINT a true; }; node_2(){ optional 0; }; node_3(){ oneormore 1; }
node_4(){ required 2 3; }; node_5(){ required 4; }; cat <<<' docopt_exit() {
[[ -n $1 ]] && printf "%s\n" "$1" >&2; printf "%s\n" "${DOC:82:58}" >&2; exit 1
}'; unset var___namespace var_FINGERPRINT; parse 5 "$@"
local prefix=${DOCOPT_PREFIX:-''}; unset "${prefix}__namespace" \
"${prefix}FINGERPRINT"; eval "${prefix}"'__namespace=${var___namespace:-}'
if declare -p var_FINGERPRINT >/dev/null 2>&1; then
eval "${prefix}"'FINGERPRINT=("${var_FINGERPRINT[@]}")'; else
eval "${prefix}"'FINGERPRINT=()'; fi; local docopt_i=1
[[ $BASH_VERSION =~ ^4.3 ]] && docopt_i=2; for ((;docopt_i>0;docopt_i--)); do
declare -p "${prefix}__namespace" "${prefix}FINGERPRINT"; done; }
# docopt parser above, complete command for generating this parser is `docopt.sh --library='"$pkgroot/.upkg/andsens/docopt.sh/docopt-lib.sh"' k8s-secrets.sh`
  eval "$(docopt "$@")"

  # shellcheck disable=2154
  local fingerprint namespace=$__namespace cert secret_name
  [[ -n $namespace ]] || namespace=${POD_NAMESPACE:?"Either --namespace or \$POD_NAMESPACE must be specified"}
  # shellcheck disable=2153
  for fingerprint in "${FINGERPRINT[@]}"; do
    secret_name=${fingerprint,,}
    cert=$("$pkgroot/fetch-ca.sh" "$fingerprint")
    printf '
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: %s
  namespace: %s
data:
  ca.crt: %s
' "$secret_name" "$namespace" "$(base64 -w0 <<<"$cert")" | kubectl apply -f - | LOGPROGRAM=kubectl tee_info
  done
}

main "$@"
