
FROM ubuntu:16.04

RUN apt update

RUN apt install -y vim openjdk-8-jdk ca-certificates openjdk-8-jdk pkg-config gcc make ant g++ maven git libboost-dev libcurl4-openssl-dev libssl-dev unixodbc-dev libjson0-dev cmake libgtest-dev postgresql-9.5 postgresql-client-9.5 postgresql-client-common postgresql-contrib-9.5 odbc-postgresql cmake libgtest-dev sshpass wget

RUN echo "export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64" >> ~/.bashrc

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64

RUN chsh -s /bin/bash

RUN mkdir /root/odl

WORKDIR /root/odl

RUN wget https://nexus.opendaylight.org/content/repositories/public/org/opendaylight/integration/distribution-karaf/0.6.2-Carbon/distribution-karaf-0.6.2-Carbon.tar.gz

RUN tar -zxf distribution-karaf-0.6.2-Carbon.tar.gz

RUN ln -s distribution-karaf-0.6.2-Carbon main

# TODO
RUN apt install -y screen net-tools

COPY setup-karaf.sh .

RUN ./setup-karaf.sh

# # VTN installation 

RUN cp -r /usr/src/gtest/ /root/gtest-work/

WORKDIR /root/gtest-work
RUN cmake CMakeLists.txt 
RUN make -j $(cat /proc/cpuinfo | grep -E '^processor' | wc -l)
RUN cp *.a /usr/lib

RUN mkdir -p /root/.m2
RUN wget -q -O - https://raw.githubusercontent.com/opendaylight/odlparent/master/settings.xml > ~/.m2/settings.xml

WORKDIR /root/odl/

RUN git clone https://github.com/opendaylight/vtn.git

WORKDIR /root/odl/vtn
RUN git checkout release/oxygen

# TODO
RUN apt install -y python

WORKDIR /root/odl/vtn/coordinator
RUN mvn -T $(cat /proc/cpuinfo | grep -E '^processor' | wc -l) -f dist/pom.xml install
RUN ./configure
RUN make -j $(cat /proc/cpuinfo | grep -E '^processor' | wc -l)
RUN make install

RUN /usr/local/vtn/sbin/db_setup
RUN /usr/local/vtn/bin/vtn_start

WORKDIR /root/odl/
ENTRYPOINT /root/odl/main/bin/karaf






