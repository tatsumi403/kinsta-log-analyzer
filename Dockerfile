# Multi-stage build for optimized Docker image

# --- Builder Stage ---
FROM golang:1.22-alpine AS builder

# Install necessary packages
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user
RUN adduser -D -s /bin/sh -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0: Build static binary
# GOOS=linux: Target Linux
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o log-analyzer ./cmd/log-analyzer

# --- Final Stage ---
FROM alpine:latest

# Install ca-certificates for HTTPS requests (if needed)
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN adduser -D -s /bin/sh -u 1000 appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/log-analyzer .

# Copy default configuration
COPY --from=builder /app/config.yaml .

# Create directories for logs and output
RUN mkdir -p /app/logs /app/output && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set default command
ENTRYPOINT ["./log-analyzer"]

# Default command shows help
CMD ["--help"]

# Labels for metadata
LABEL maintainer="Claude Code"
LABEL description="Kinsta Nginx Log Analyzer"
LABEL version="1.0.0"

# Health check (optional)
HEALTHCHECK NONE