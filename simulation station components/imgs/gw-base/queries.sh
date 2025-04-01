#!/bin/bash

set -e

# start mysql
find /var/lib/mysql -type f -exec touch {} \; && service mysql start

# set root password
mysqladmin -u root password root

# initiate database
mysql -u root -proot -e "create database if not exists snort;"
mysql -u root -proot -D snort -e "source /root/barnyard2-master/schemas/create_mysql"
mysql -u root -proot -e "grant all privileges on snort.* to snort@'%' identified by 'snort'; flush privileges;"

# mysql -u root -proot -D snort -e "GRANT ALL ON `snort`.* to 'snort'@'localhost' IDENTIFIED BY 'snort';"
# mysql -u root -proot -D snort -e "grant create, insert, select, delete, update on snort.* to 'snort'@'localhost';"

