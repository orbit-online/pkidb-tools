FROM alpine:3.18.2
ARG BUILT_BY=<unknown> BUILD_TOOL=cli
LABEL cr.orbit.dev/build-src="https://github.com/orbit-online/pkidb-tools" cr.orbit.dev/built-by=$BUILT_BY cr.orbit.dev/build-tool=$BUILD_TOOL

RUN apk add --update --no-cache bash jq git openssl curl perl-utils
SHELL ["/bin/bash", "-ec"]

RUN wget -q "https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl" && \
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

WORKDIR /pkidb-tools
COPY common.sh k8s-secrets/upkg.json /pkidb-tools/
COPY --chmod=0755 bin/pkidb-k8s-secrets bin/pkidb-ca /pkidb-tools/
RUN bash -ec 'u=https://github.com/orbit-online/upkg/releases/download/v0.26.3/upkg-install.tar.gz;\
t=$(mktemp); trap "rm \"$t\"" EXIT;wget -qO"$t" "$u" || curl -fsLo"$t" "$u";\
shasum -a 256 -c <(echo "ae99b32cd7cd97a8d102999c8c87bc40844bf9994925dd432b8c0347bb23dc46  $t");\
tar xzC /usr/local -f "$t"'

ENTRYPOINT ["/pkidb-tools/pkidb-k8s-secrets"]
