FROM alpine:3.16 as builder

ARG CXXFLAGS="-DSTACK_TRACE:BOOL -DELPP_FEATURE_CRASH_LOG"
ARG HAVEN_VERSION=v3.1.9d
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG USE_SINGLE_BUILDDIR=1

RUN apk --no-cache add git
RUN apk --no-cache add bash
RUN apk --no-cache add unbound-dev
RUN apk --no-cache add build-base
RUN apk --no-cache add patch
RUN apk --no-cache add cmake
RUN apk --no-cache add openssl-dev
RUN apk --no-cache add linux-headers
RUN apk --no-cache add zeromq-dev
RUN apk --no-cache add libexecinfo-dev
RUN apk --no-cache add libunwind-dev
RUN apk --no-cache add boost-dev
RUN apk --no-cache add boost-static
RUN apk --no-cache add icu-data-full
RUN apk --no-cache add zip

COPY . /haven-main
WORKDIR /haven-main
RUN git submodule update --init --force
RUN if [ "$TARGETARCH" = "amd64" ]; then export build=x86_64; fi; \
if  [ "$TARGETARCH" = "386" ]; then export build=i686; fi; \
if [ "$TARGETARCH" = "arm" ]; then export build=${TARGETARCH}${TARGETVARIANT}; fi; \
if [ "$TARGETARCH" = "arm64" ]; then export build=armv8; fi; \
make release-static-${TARGETOS}-${build} -j $(($(nproc) + 1))

RUN build/release/bin/havend --version

RUN zip /lib.zip $(ldd build/release/bin/* | grep -E '/[^\ ]*' -o)

FROM alpine:3.16 as runner

COPY --from=builder /lib.zip .
RUN unzip -o lib.zip && rm -rf lib.zip


#RUN apk update
RUN apk --no-cache add \
#  libexecinfo \
#  libzmq \
#  boost-system \
#  boost-thread \
#  boost-chrono \
#  boost-regex \
#  boost-serialization \
#  boost-locale \
#  boost-date_time \
#  boost-program_options \
#  boost-filesystem \
  bash \
  su-exec \
  zip

# Create haven user
RUN addgroup haven && \
  adduser --system -G haven --disabled-password haven

COPY --from=builder /haven-main/build/release/bin/* /usr/local/bin/
COPY .docker/network/* /etc/haven/conf.d/
COPY .docker/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["havend", "--config-file","/etc/haven/conf.d/mainnet.conf"]

EXPOSE 17749 17750 27749 27750 37749 37750
