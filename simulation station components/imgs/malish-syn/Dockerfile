
FROM iman/syn-attacker:1

COPY *.sh /root/

RUN apt-get install -y iptables tmux screen net-tools iputils-ping tcpdump

ENTRYPOINT ["/bin/bash", "/root/entry.sh"]

