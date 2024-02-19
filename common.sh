#!/usr/bin/env bash

[[ -n "$PKIDBURL" ]] || fatal "\$PKIDBURL is not set, unable to continue."

check_all_deps() {
  checkdeps openssl curl
}

get_ca_url() {
  local fingerprint=$1
  check_fp_format "$fingerprint"
  printf "%s/cas/%s.pem" "$PKIDBURL" "$fingerprint"
}

get_crl_url() {
  local pkiname=$1
  printf "%s/crls/%s.pem" "$PKIDBURL" "$pkiname"
}

get_krl_url() {
  local pkiname=$1
  printf "%s/krls/%s.pem" "$PKIDBURL" "$pkiname"
}

generate_fingerprint() {
  debug "Generating SHA-256 fingerprint for a certificate"
  openssl x509 -noout -fingerprint -sha256 2> >(LOGPROGRAM=openssl tee_verbose) | cut -d= -f2 | sed s/://g
}

has_changed() {
  local url=$1 cache_path=$2 head_status
  if [[ ! -e $cache_path ]]; then
    return 0
  fi
  if ! head_status=$(curl -fsIA "$(basename "$0")" -H "If-None-Match: \"$(md5sum "$cache_path" | cut -d' ' -f1)\"" -w "%{http_code}\n" -o /dev/null "$url"); then
    error "HEAD request to '%s' failed" "$url"
    return 2
  fi
  if [[ $head_status = '304' ]]; then
    verbose 'The file at "%s" has not changed (status %s)' "$cache_path" "$head_status"
    return 3
  else
    verbose 'The file at "%s" has been updated on the remote (status %s)' "$cache_path" "$head_status"
    return 0
  fi
}

download() {
  local url=$1
  verbose "Fetching from %s" "$url"
  curl -fsA "$(basename "$0")" "$url"
}

check_fp_format() {
  local fingerprint=$1
  if [[ ! $fingerprint =~ ^[0-9a-fA-F]{64}$ ]]; then
    error "The fingerprint '%s' is not a valid SHA-256 hash" "$fingerprint"
    return 1
  fi
}

get_pubkey() {
  openssl x509 -pubkey -noout 2> >(LOGPROGRAM=openssl tee_verbose)
}

get_subject_field() {
  local oid=$1 name=$2
  openssl x509 -subject -noout -nameopt esc_ctrl,esc_msb,sep_multiline,lname | \
    tail -n+2 | grep "\(^\|[[:space:]]\)\($oid\|$name\)=" | cut -d= -f2
}

get_sans() {
  openssl x509 -noout -ext subjectAltName | tail -n1 | grep -Po '(?<=DNS:)[^,]+'
}
