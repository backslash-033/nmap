FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    nmap \
    libpcap-dev \
    zsh \
    nginx \
    netcat-traditional \
    tcpdump \
    curl \
    && apt-get clean

RUN mkdir -p /opt/nmap

EXPOSE 80

WORKDIR /opt/nmap

CMD ["sh", "-c", "service nginx start && bash"]