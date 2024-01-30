#!/usr/bin/env bash

pkidb_step() {
  set -eo pipefail; shopt -s inherit_errexit
  local pkgroot; pkgroot=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
  PATH=$("$pkgroot/.upkg/.bin/path_prepend" "$pkgroot/.upkg/.bin")
  source "$pkgroot/.upkg/orbit-online/records.sh/records.sh"
  source "$pkgroot/common.sh"
  check_all_deps

  [[ -n $STEP_ROOT_FP ]] || fatal "\$STEP_ROOT_FP is not defined"
  export STEP_URL
  STEP_URL=$(LOGLEVEL=warning "$pkgroot/pkidb-ca.sh" "$STEP_ROOT_FP" | get_subject_field "2.5.4.87" url)
  exec step "$@"
}

pkidb_step "$@"
