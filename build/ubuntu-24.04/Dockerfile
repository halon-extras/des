FROM --platform=linux/amd64 ubuntu:24.04
LABEL org.opencontainers.image.authors="support@halon.io"

ARG HALON_REPO_USER
ARG HALON_REPO_PASS

RUN apt-get update && apt-get install -y wget gnupg
RUN apt-get update && apt-get install -y apt-transport-https

RUN wget -qO - https://raw.githubusercontent.com/halon/pgp-keys/master/pgp-keys/7F0A73B5.gpg | tee /usr/share/keyrings/halon-archive-keyring.gpg > /dev/null
RUN echo "deb [arch=`dpkg --print-architecture` signed-by=/usr/share/keyrings/halon-archive-keyring.gpg] https://repo.halon.io/ noble stable" >> /etc/apt/sources.list.d/halon.list
RUN echo "machine repo.halon.io login ${HALON_REPO_USER} password ${HALON_REPO_PASS}" >> /etc/apt/auth.conf
RUN apt-get update && apt-get install -y halon=6.3.0

RUN apt-get update && apt-get install -y build-essential cmake file
RUN echo -n "UBU2404" > /OSRELEASE.txt

RUN mkdir /build
RUN cd /build \
    && wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz \
    && tar -xzvf openssl-1.1.1w.tar.gz && cd openssl-1.1.1w \
    && ./config --prefix=/external --libdir=lib \
    && make && make install_sw
RUN rm -rf /build

COPY build.sh /build.sh
CMD ["/build.sh"]
