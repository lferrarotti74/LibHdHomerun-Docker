FROM ubuntu:25.04 AS stage

RUN apt update && apt-get upgrade && apt install build-essential git -y \
&& git clone https://github.com/Silicondust/libhdhomerun.git \
&& cd libhdhomerun && make -j$(nproc)

FROM ubuntu:25.04

LABEL org.opencontainers.image.title="LibHdHomerun-Docker"
LABEL org.opencontainers.image.version="latest"
LABEL org.opencontainers.image.description="Silicondust library and cli utility for controlling HDHomeRun tuners"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/lferrarotti74/LibHdHomerun-Docker"

RUN apt update && apt-get upgrade -y \
    && mkdir -p /libhdhomerun

COPY --from=stage /libhdhomerun/hdhomerun_config /libhdhomerun/libhdhomerun.so /libhdhomerun/
