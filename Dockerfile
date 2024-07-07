FROM ubuntu:24.10 as stage

RUN apt update && apt install build-essential git -y \
&& git clone https://github.com/Silicondust/libhdhomerun.git \
&& cd libhdhomerun && make -j$(nproc)

FROM ubuntu:24.10

RUN mkdir -p /libhdhomerun
COPY --from=stage /libhdhomerun/hdhomerun_config /libhdhomerun
COPY --from=stage /libhdhomerun/libhdhomerun.so /libhdhomerun
