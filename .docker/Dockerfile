FROM alpine:3.12 as builder

ARG CXXFLAGS="-DSTACK_TRACE:BOOL -DELPP_FEATURE_CRASH_LOG"
ARG HAVEN_VERSION=v2.0.0
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG USE_SINGLE_BUILDDIR=1

RUN apk --no-cache add git
RUN apk --no-cache add bash
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

COPY . /haven-main
WORKDIR /haven-main
RUN git submodule update --init --force
RUN if [ "$TARGETARCH" = "amd64" ]; then export build=x86_64; fi; \
if  [ "$TARGETARCH" = "386" ]; then export build=i686; fi; \
if [ "$TARGETARCH" = "arm" ]; then export build=${TARGETARCH}${TARGETVARIANT}; fi; \
if [ "$TARGETARCH" = "arm64" ]; then export build=armv8; fi; \
make release-static-${TARGETOS}-${build} -j $(($(nproc) + 1))

RUN build/release/bin/havend --version

FROM alpine:3.12 as runner

RUN apk update
RUN apk --no-cache add \
  libexecinfo \
  libzmq \
  boost-system \
  boost-thread \
  boost-chrono \
  boost-regex \
  boost-serialization \
  boost-locale \
  boost-date_time \
  boost-program_options \
  boost-filesystem \
  bash \
  su-exec

# Create haven user
RUN addgroup haven && \
  adduser --system -G haven --disabled-password haven && \
	mkdir -p /wallet /home/haven/.haven && \
	chown -R haven:haven /home/haven/.haven && \
	chown -R haven:haven /wallet

VOLUME /home/haven/.haven

VOLUME /wallet

COPY --from=builder /haven-main/build/release/bin/* /usr/local/bin/

# switch to user haven
USER haven

CMD ["havend", "--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=17749", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=17750", "--non-interactive", "--confirm-external-bind"]

EXPOSE 17749 17750
