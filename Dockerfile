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
RUN go build -trimpath -ldflags="-s -w" -o server main.go


FROM gcr.io/distroless/static
COPY --from=builder /app/server /app/server
ENTRYPOINT ["/app/server", "server"]
