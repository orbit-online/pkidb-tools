FROM alpine:3.18.2
ARG BUILT_BY=<unknown> BUILD_TOOL=cli
LABEL cr.orbit.dev/build-src="https://github.com/orbit-online/pkidb-tools" cr.orbit.dev/built-by=$BUILT_BY cr.orbit.dev/build-tool=$BUILD_TOOL

RUN apk add --update --no-cache bash jq git openssl curl perl-utils
SHELL ["/bin/bash", "-ec"]

RUN wget -q "https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl" && \
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

RUN wget -qO- https://raw.githubusercontent.com/orbit-online/upkg/v0.12.3/upkg.sh | (\
  set +e; IFS='' read -r -d $'\0' src; set -e;\
  printf '%s' "$src" | shasum -a 256 -c <(printf 'cd66df6dc96d4edf6dfb57c531da9c17653ea3482f5a270a03cd2211a3e3be00  -');\
  bash -c "set - install -g orbit-online/upkg@v0.12.3; $src")

WORKDIR /pkidb-tools
COPY common.sh k8s-secrets/upkg.json /pkidb-tools
COPY --chmod=0755 pkidb-k8s-secrets.sh pkidb-ca.sh /pkidb-tools
RUN upkg install

ENTRYPOINT ["/pkidb-tools/pkidb-k8s-secrets.sh"]
