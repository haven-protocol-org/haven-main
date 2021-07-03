FROM alpine:3.12 as builder

ARG CXXFLAGS="-DSTACK_TRACE:BOOL -DELPP_FEATURE_CRASH_LOG"
ARG HAVEN_VERSION=v1.3.1
ARG TARGETOS
ARG TARGETARCH 
ARG TARGETVARIANT

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


WORKDIR /
RUN git clone --recursive --depth 1 --branch ${HAVEN_VERSION} --single-branch https://github.com/haven-protocol-org/haven-offshore.git 
WORKDIR /haven-offshore
RUN if [ "$TARGETARCH" = "amd64" ]; then export build=x86_64; fi; \
if  [ "$TARGETARCH" = "386" ]; then export build=i686; fi; \
if [ "$TARGETARCH" = "arm" ]; then export build=${TARGETARCH}${TARGETVARIANT}; fi; \
if [ "$TARGETARCH" = "arm64" ]; then export build=armv8; fi; \
./build-haven.sh release-static-${TARGETOS}-${build} -j4

RUN monero/build/release/bin/havend --version

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

COPY --from=builder /haven-offshore/monero/build/release/bin/* /usr/local/bin/

ADD ./docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh
RUN chmod a+x /usr/local/bin/docker_entrypoint.sh

# switch to user haven
USER haven

CMD ["havend", "--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=17749", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=17750", "--non-interactive", "--confirm-external-bind"]

EXPOSE 17749 17750
