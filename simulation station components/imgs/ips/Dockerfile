FROM mg-gw-base

COPY *.sh /root/

# Add DAQ rules
RUN /root/add-daq-rules.sh

COPY local.rules /etc/snort/rules/

COPY decoder.rules /etc/snort/preproc_rules/

# Configure start-up script
CMD ["/bin/bash", "/root/entry.sh"]


