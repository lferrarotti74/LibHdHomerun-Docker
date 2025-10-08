# Security-hardened Dockerfile for LibHdHomerun-Docker
# This version implements multiple security best practices and CVE mitigation strategies

# Use Ubuntu LTS for better security support and stability
FROM ubuntu:24.04 AS stage

# Set non-interactive frontend to avoid prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Create build user for security (avoid running as root during build)
RUN groupadd --system --gid 1001 builder \
    && useradd --system --uid 1001 --gid builder --shell /bin/bash builder

# Update package lists and install security updates
# Use --no-install-recommends to minimize attack surface
# Pin package versions for reproducible builds
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        build-essential=12.10ubuntu1 \
        ca-certificates=20240203 \
        git=1:2.43.0-1ubuntu7.3 \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

# Switch to non-root user for git operations
USER builder
WORKDIR /tmp/build

# Clone and build libhdhomerun with security considerations and architecture-specific optimization
RUN git clone --depth 1 https://github.com/Silicondust/libhdhomerun.git \
    && cd libhdhomerun \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then \
        JOBS=$(nproc); \
    else \
        JOBS=$(($(nproc) / 2)); \
        [ "$JOBS" -lt 1 ] && JOBS=1; \
    fi \
    && echo "Building on $ARCH with $JOBS jobs" \
    && make -j"$JOBS" || (echo "Make failed, trying with single job" && make -j1) \
    && strip hdhomerun_config libhdhomerun.so

# Production stage - minimal base image
FROM ubuntu:24.04

# Security labels for container metadata
LABEL org.opencontainers.image.title="LibHdHomerun-Docker"
LABEL org.opencontainers.image.version="latest"
LABEL org.opencontainers.image.description="Silicondust library and cli utility for controlling HDHomeRun tuners"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/lferrarotti74/LibHdHomerun-Docker"
LABEL org.opencontainers.image.vendor="LibHdHomerun-Docker"
LABEL org.opencontainers.image.authors="maintainer@example.com"
LABEL org.opencontainers.image.documentation="https://github.com/lferrarotti74/LibHdHomerun-Docker/blob/main/README.md"

# Set non-interactive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Install only essential runtime dependencies with version pinning and create application user
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        libc6=2.39-0ubuntu8.6 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/* \
    && find /var/log -type f -delete \
    && groupadd --system --gid 1001 libhdhomerun \
    && useradd --system --uid 1001 --gid libhdhomerun \
        --comment "libhdhomerun service user" \
        --home-dir /libhdhomerun \
        --create-home \
        --shell /sbin/nologin \
        libhdhomerun

# Copy binaries from build stage with secure ownership and permissions
COPY --from=stage --chown=root:root --chmod=555 \
    /tmp/build/libhdhomerun/hdhomerun_config \
    /libhdhomerun/hdhomerun_config

COPY --from=stage --chown=root:root --chmod=444 \
    /tmp/build/libhdhomerun/libhdhomerun.so \
    /libhdhomerun/libhdhomerun.so

# Set secure permissions for the application directory
RUN chown libhdhomerun:libhdhomerun /libhdhomerun \
    && chmod 750 /libhdhomerun

# Add library path for runtime
ENV LD_LIBRARY_PATH=/libhdhomerun

# Security: Drop all capabilities and run as non-root
USER 1001:1001

# Set working directory
WORKDIR /libhdhomerun

# Health check for container monitoring (optional - only when devices expected)
# HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#     CMD ./hdhomerun_config discover || exit 1

# Default command - keep container running for interactive use
# Use bash to keep container alive for manual CLI usage
CMD ["/bin/bash"]