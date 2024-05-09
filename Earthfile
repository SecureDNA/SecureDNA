# requires `earthly`: https://earthly.dev
VERSION 0.6

dev:
    FROM +debian-base
    WORKDIR /app

    BUILD +client-image
    BUILD +keyserver-image
    BUILD +hdbserver-image

keyserver-image:
    FROM +debian-base
    WORKDIR /keyserver
    EXPOSE 80

    COPY +build-rust/build/keyserver .

    ARG EARTHLY_GIT_SHORT_HASH
    ARG SECUREDNA_TAG

    CMD ["./keyserver"]

    SAVE IMAGE --push ghcr.io/securedna/keyserver:${SECUREDNA_TAG} ghcr.io/securedna/keyserver:${EARTHLY_GIT_SHORT_HASH}

hdbserver-image:
    FROM +debian-base
    WORKDIR /hdb
    EXPOSE 80

    COPY +build-rust/build/hdbserver .

    ARG EARTHLY_GIT_SHORT_HASH
    ARG SECUREDNA_TAG

    CMD ["./hdbserver"]

    SAVE IMAGE --push ghcr.io/securedna/hdbserver:${SECUREDNA_TAG} ghcr.io/securedna/hdbserver:${EARTHLY_GIT_SHORT_HASH}

client-image:
    FROM gcr.io/distroless/cc-debian12
    WORKDIR /client
    EXPOSE 80

    COPY +build-rust/build/synthclient .

    ARG EARTHLY_GIT_SHORT_HASH
    ARG SECUREDNA_TAG

    CMD ["./synthclient"]

    SAVE IMAGE --push ghcr.io/securedna/client:${SECUREDNA_TAG} ghcr.io/securedna/client:${EARTHLY_GIT_SHORT_HASH}

## builders

debian-base:
    FROM bitnami/minideb:bookworm
    RUN apt-get update \
        && apt-get install -y --no-install-recommends ca-certificates \
        && rm -rf /var/lib/apt/lists/*

    RUN update-ca-certificates

# rust builder

rust-base:
    FROM rust:1.76.0-bookworm
    ENV NODE_VERSION=18.17.1
    RUN apt install -y curl
    RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
    ENV NVM_DIR=/root/.nvm
    RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION}
    RUN . "$NVM_DIR/nvm.sh" && nvm use v${NODE_VERSION}
    RUN . "$NVM_DIR/nvm.sh" && nvm alias default v${NODE_VERSION}
    ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin/:${PATH}"
    RUN node --version
    RUN npm --version
    RUN npm install -g pnpm
    RUN cargo install --debug cargo-chef --locked --version '>=0.1.48'

prepare-cache:
    FROM +rust-base
    WORKDIR /rust
    COPY . .
    RUN cargo chef prepare --recipe-path /recipe.json
    SAVE ARTIFACT /recipe.json

build-cache:
    FROM +rust-base
    WORKDIR /rust
    COPY +prepare-cache/recipe.json /recipe.json
    # Build dependencies - this is the caching Docker layer!
    RUN cargo chef cook --release --recipe-path /recipe.json
    SAVE ARTIFACT target
    SAVE ARTIFACT $CARGO_HOME cargo_home

build-rust:
    FROM +rust-base

    COPY . .
    # hack to get vergen to find the git repo, for some reason it isn't looking at the monorepo root
    RUN cp -r .git crates/securedna_versioning/.git

    COPY +build-cache/cargo_home $CARGO_HOME
    COPY +build-cache/target target

    RUN cargo build --release -p synthclient -p keyserver -p hdbserver
    SAVE ARTIFACT target/release build
