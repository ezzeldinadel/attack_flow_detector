
Install Java 8
--------------

```
add-apt-repository ppa:webupd8team/java
apt update

apt-get install -y oracle-java8-installer

echo "export JAVA_HOME=/usr/lib/jvm/java-8-oracle/" >> ~/.bashrc
. ~/.bashrc
```

Donwnload and install Karaf
---------------------------

```
mkdir odl
cd odl

wget https://nexus.opendaylight.org/content/repositories/public/org/opendaylight/integration/distribution-karaf/0.6.2-Carbon/distribution-karaf-0.6.2-Carbon.tar.gz

tar -zxf distribution-karaf-0.6.2-Carbon.tar.gz

cd distribution-karaf-0.6.2-Carbon
```

And then run the Karaf shell which starts OpenDaylight:

```
bin/karaf
```

Download Dependencies
---------------------

**Inside Karaf shell** install the required features:

```
feature:repo-refresh

feature:install odl-dluxapps-applications odl-restconf odl-l2switch-switch odl-mdsal-apidocs odl-dluxapps-applications odl-mdsal-apidocs odl-openflowplugin-southbound odl-vtn-manager-rest odl-l2switch-hosttracker
```

If you want automatic L2 switching you gotta install the following:

```
feature:install odl-l2switch-all
```

To see the list of available features you can always run:

```
feature-list
```

It has grep too:

```
feature-list | grep dlux
```

Installing as service
---------------------

You can create a simple systemctl service:

```
ln -s /root/odl/distribution-karaf-0.6.2-Carbon /etc/sdn

echo -e "[Unit]\nDescription=OpenDayLight Controller\nAfter=network.target\n[Service]\nType=forking\nUser=root\nExecStart=/etc/sdn/bin/start\nRestart=on-abort\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/opendaylight.service

```

And enable it this way:

```
systemctl daemon-reload
systemctl enable opendaylight
systemctl start opendaylight
```

Or, you can always just use screen instead:

```
screen -d -m bash -c '/etc/sdn/bin/karaf server'
```

Install VTN coordination
------------------------

To use Virtual Tenant Networks on OpenDaylight, in addition to installing the **VTN manager** feature which we did above, you have to run an external application called the **VTN coordinator** which manages vBridges, vSwitches and basically makes the whole thing work.

Install dependencies:

```
apt-get install pkg-config gcc make  ant g++ maven git libboost-dev libcurl4-openssl-dev libssl-dev openjdk-7-jdk unixodbc-dev libjson0-dev cmake libgtest-dev
```

and also PostgreSQL:

```
apt-get install  postgresql-9.5 postgresql-client-9.5 postgresql-client-common postgresql-contrib-9.5 odbc-postgresql
```

Install gtest-work:

```
apt-get install cmake libgtest-dev
cp -R /usr/src/gtest gtest-work
cd gtest-work
cmake CMakeLists.txt
make
sudo cp *.a /usr/lib
cd ..
rm -rf gtest-work
```

Fix Maven m2 settings:

```
mkdir -p ~/.m2

cp -n ~/.m2/settings.xml{,.orig} ; \
wget -q -O - https://raw.githubusercontent.com/opendaylight/odlparent/master/settings.xml > ~/.m2/settings.xml
```

Now it's time to build ODL VTN Coordinator:

```
# Get number of cores
cores=$(cat /proc/cpuinfo  | grep -E '^processor' | wc -l)

# Back to ODL folder to build
cd ~/odl

# Clone & check-out
git clone https://github.com/opendaylight/vtn.git
cd vtn
git checkout release/oxygen

# Build the Java part
cd coordinator
mvn -T $cores -f dist/pom.xml install

# Build the C part
./configure
make -j $cores
make install

```

Run VTN Coordinator
-------------------

Set-up the database:

```
/usr/local/vtn/sbin/db_setup
```

And run the coordinator:

```
/usr/local/vtn/bin/vtn_start
```

You can check the status using:

```
/usr/local/vtn/bin/unc_dmctl status
```

And there should be 3 different services running.

*Voila!*
