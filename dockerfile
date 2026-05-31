FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /zingpass ./cmd/zingpass

FROM alpine:3.20
COPY --from=builder /zingpass /zingpass
ENTRYPOINT ["/zingpass"]
