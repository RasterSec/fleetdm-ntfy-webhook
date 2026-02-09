FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o fleet-ntfy-webhook .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/fleet-ntfy-webhook .

EXPOSE 8080

USER nobody

ENTRYPOINT ["./fleet-ntfy-webhook"]
