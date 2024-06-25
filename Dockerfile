FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    nmap \
    libpcap-dev \
    zsh \
    && apt-get clean

RUN mkdir -p /opt/nmap

WORKDIR /opt/nmap

ENTRYPOINT ["bash"]