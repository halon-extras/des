FROM --platform=linux/amd64 ubuntu:20.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update && apt-get install -y wget gnupg
RUN apt-get update && apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/changelog/master/pgp-keys/7F0A73B5.asc | apt-key add -
RUN echo "deb https://repo.halon.io/ focal stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=5.10.0

RUN apt-get update && apt-get install -y git build-essential cmake
RUN echo -n "UBU2004" > /OSRELEASE.txt

RUN mkdir /build
RUN cd /build \
    && wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz \
    && tar -xzvf openssl-1.1.1w.tar.gz && cd openssl-1.1.1w \
    && ./config --prefix=/external --libdir=lib \
    && make && make install_sw
RUN rm -rf /build

COPY build.sh /build.sh
CMD ["/build.sh"]
