FROM rust:1.61

# 2. Copy the files in your machine to the Docker image
COPY ./ ./

# Build your program for release
ADD /containers/demo/vault-ca.crt /certs/

RUN set -ex; \
    useradd --home-dir /usr/lib/spark --create-home --user-group spark

RUN cargo build --verbose

# Run the binary
ENTRYPOINT ["./target/debug/vault-env-exec"]
CMD ["spark:spark", "--", "echo", "hi"]
