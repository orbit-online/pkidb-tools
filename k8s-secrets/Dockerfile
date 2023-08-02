FROM alpine:3.18.2

RUN apk add --update --no-cache bash jq git openssl curl perl-utils
SHELL ["/bin/bash", "-ec"]

RUN wget -q "https://dl.k8s.io/release/v1.27.4/bin/linux/amd64/kubectl" && \
  install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

RUN wget -qO- https://raw.githubusercontent.com/orbit-online/upkg/v0.9.11/upkg.sh | (\
  set +e; IFS='' read -r -d $'\0' src; set -e;\
  printf '%s' "$src" | shasum -a 256 -c <(printf '2ce14fb5f7c1f6423789e23a16be70c4aac5a930a8638ae4e2e7663e0cce46df  -');\
  bash -c "set - install -g orbit-online/upkg@v0.9.11; $src")

WORKDIR /pkidb-tools
COPY common.sh k8s-secrets/upkg.json /pkidb-tools
COPY --chmod=0755 k8s-secrets.sh fetch-ca.sh /pkidb-tools
RUN upkg install

ENTRYPOINT ["/pkidb-tools/k8s-secrets.sh"]
