
FROM mg-host-base

USER root

RUN apt-get install -y iptables tmux screen net-tools iputils-ping tcpdump git hping3 python-pip

WORKDIR /root/

COPY *.sh /root/

COPY infection-gemel /root/infection-gemel

WORKDIR /root/infection-gemel

RUN pip install -r ./syn-flood/requirements.txt

ENTRYPOINT ["/bin/bash", "/root/entry.sh"]

