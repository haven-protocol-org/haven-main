FROM alpine:3.16 as builder

ARG CXXFLAGS="-DSTACK_TRACE:BOOL -DELPP_FEATURE_CRASH_LOG"

ENV CCACHE_DIR /haven-main/.ccache

ARG TARGET=linux-x86_64
ARG USE_SINGLE_BUILDDIR=1


RUN apk --no-cache add git bash unbound-dev build-base patch cmake openssl-dev linux-headers zeromq-dev libexecinfo-dev libunwind-dev boost-dev boost-static icu-data-full zip ccache build-base

COPY . /haven-main
WORKDIR /haven-main
RUN git submodule update --init --force
RUN ccache --max-size=150M \
  && ccache --set-config=compression=true \
  && PATH="/usr/lib/ccache:${PATH}" make release-static-${TARGET} -j $(($(nproc) + 1))

RUN zip /lib.zip $(ldd build/release/bin/* | grep -E '/[^\ ]*' -o)

FROM alpine:3.16 as runner

COPY --from=builder /lib.zip .
RUN unzip -o lib.zip && rm -rf lib.zip

#RUN apk update
RUN apk --no-cache add \
  libzmq \
  bash \
  su-exec \
  zip

# Create haven user
RUN addgroup haven && \
  adduser --system -G haven --disabled-password haven

COPY --from=builder /haven-main/build/release/bin/* /usr/local/bin/
COPY .docker/network/* /etc/haven/conf.d/
COPY .docker/docker-entrypoint.sh /docker-entrypoint.sh

RUN havend --version

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["havend", "--config-file","/etc/haven/conf.d/mainnet.conf"]

EXPOSE 17749 17750 27749 27750 37749 37750