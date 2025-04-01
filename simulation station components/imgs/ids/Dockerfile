FROM mg-gw-base

COPY local.rules /etc/snort/rules/

# Configure start-up script
COPY *.sh /root/
CMD ["/bin/bash", "/root/entry.sh"]


