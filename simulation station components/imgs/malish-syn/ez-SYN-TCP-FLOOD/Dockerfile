FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update

RUN apt-get install -y build-essential python3.6 python3.6-dev python3-pip python3.6-venv
RUN python3.6 -m pip install pip --upgrade

RUN update-alternatives --remove python /usr/bin/python2
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.6 10

# =============================================

COPY src /root/flooder

WORKDIR /root/flooder

RUN pip3 install -r requirements.txt

RUN mkdir out

USER root

RUN apt-get install -y tcpdump
RUN apt-get install -y screen


