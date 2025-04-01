
FROM ubuntu:16.04

USER root

RUN apt update

# install package requirements e.g. MySQL client
COPY req /root/halsey-req
WORKDIR /root/halsey-req
RUN bash requirements.sh

# install python 3.6
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update
RUN apt-get install -y build-essential python3.6 python3.6-dev python3-pip python3.6-venv
RUN python3.6 -m pip install pip --upgrade
RUN rm /usr/bin/python3
RUN ln -s /usr/bin/python3.6 /usr/bin/python3

# install python dependencies
RUN pip3 install -r requirements.txt

# # install google cloud SDK
# RUN apt install -y curl
# RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
# RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
# RUN apt-get update && apt-get install -y google-cloud-sdk

# install gemel python dependency
WORKDIR /root/
RUN apt install -y git screen
RUN git clone --single-branch --branch mini-gemel https://github.com/haifa-foundation/gemel-sdn.git
ENV PYTHONPATH=/root/gemel-sdn

# set locale
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# # install GCloud service keys
# COPY conf/key.json /root/
# RUN gcloud auth activate-service-account --key-file=/root/key.json
# RUN gcloud config set project phdandpeasant

# copy source
COPY src /root/halsey
WORKDIR /root/halsey
CMD /root/halsey/run.sh
