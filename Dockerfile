FROM golang:1.26-alpine AS builder

# Set the working directory
WORKDIR /app

# Ensure a portable, static-ish binary
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application (strip debug info for smaller size)
ARG VERSION_ARG
RUN go build -trimpath -ldflags="-s -w -X 'github.com/skymeyer/onetime-secret/cmd.version=$VERSION_ARG'" -o ots main.go


FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=builder /app/ots /usr/bin/ots
ENTRYPOINT ["/usr/bin/ots", "server"]
