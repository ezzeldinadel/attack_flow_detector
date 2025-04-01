allow external access:

```
sed -i 's/127.0.0.1/0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

service mysql restart
```

allow access from IP 

```
grant all privileges on *.* to snort@10.142.15.212 identified by 'snort';
flush privileges;
```
