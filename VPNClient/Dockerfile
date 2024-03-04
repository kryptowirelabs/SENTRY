FROM ubuntu

RUN DEBIAN_FRONTEND=noninteractive \ 
    apt-get update \
    && apt-get install -y iptables \
    openvpn

COPY config.ovpn /usr/local/bin

ENTRYPOINT [ "tail" ]
CMD ["-f","/dev/null"]
