FROM alpine:3.18.2
ARG BUILT_BY=<unknown> BUILD_TOOL=cli
LABEL cr.orbit.dev/build-src="https://github.com/orbit-online/pkidb-tools" cr.orbit.dev/built-by=$BUILT_BY cr.orbit.dev/build-tool=$BUILD_TOOL

RUN apk add --update --no-cache bash jq git openssl curl perl-utils
SHELL ["/bin/bash", "-ec"]

RUN wget -q "https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl" && \
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

WORKDIR /pkidb-tools
COPY common.sh k8s-secrets/upkg.json /pkidb-tools
COPY --chmod=0755 pkidb-k8s-secrets.sh pkidb-ca.sh /pkidb-tools
RUN bash -ec 'src=$(wget -qO- https://raw.githubusercontent.com/orbit-online/upkg/v0.14.0/upkg.sh); \
shasum -a 256 -c <(printf "8312d0fa0e47ff22387086021c8b096b899ff9344ca8622d80cc0d1d579dccff  -") <<<"$src"; \
set - install; eval "$src"'

ENTRYPOINT ["/pkidb-tools/pkidb-k8s-secrets.sh"]
