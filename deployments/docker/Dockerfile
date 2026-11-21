FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go run ./scripts/embed-runtime && CGO_ENABLED=0 go build -tags bundled -trimpath -ldflags='-s -w' -o /out/caphe ./cmd/caphe
RUN CAPHE_TOOL_BIN=/out/runtime /out/caphe ai status --json

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgomp1 libstdc++6 && useradd -m -u 65532 caphe
COPY --from=build /out/caphe /usr/local/bin/caphe
COPY --from=build --chown=65532:65532 /out/runtime/ /opt/caphe/runtime/
ENV CAPHE_TOOL_BIN="/opt/caphe/runtime"
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/caphe"]
