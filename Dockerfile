ARG TARGETOS
ARG TARGETARCH

FROM golang:1.24.5-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/csobrinho/traefik-s3-forward-auth
WORKDIR /go/src/github.com/csobrinho/traefik-s3-forward-auth

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/csobrinho/traefik-s3-forward-auth/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-s3-forward-auth github.com/csobrinho/traefik-s3-forward-auth/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-s3-forward-auth ./
ENTRYPOINT ["./traefik-s3-forward-auth"]