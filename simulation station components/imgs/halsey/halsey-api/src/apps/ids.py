#!/usr/bin/env python3

import MySQLdb as my

from config import GATEWAY_DB_CONF


def get_db(conf):
    db = my.connect(conf["MYSQL_DB_URL"], conf["MYSQL_DB_USER"], conf["MYSQL_DB_PASS"], conf["MYSQL_DB_NAME"])
    return db


# noinspection SqlNoDataSourceInspection
def get_events(net, min_id=0, interval=None):

    _legacy = {"ids": "vnet1", "ips": "vnet2"}

    if net.lower() in _legacy:
        net = _legacy[net.lower()]

    db = get_db(GATEWAY_DB_CONF[net])

    date_clause = "" if interval is None else \
        "AND timestamp > CURRENT_TIMESTAMP - INTERVAL {} second".format(interval)

    c = db.cursor()
    c.execute("""
        SELECT 
            e.cid, e.sid, sig_id, sig_name, 
            INET_NTOA(ip_src) as src, 
            INET_NTOA(ip_dst) as dst, 
            ip_len, ip_id 
        FROM event e
            INNER JOIN signature s ON e.signature = s.sig_id
                INNER JOIN iphdr i ON i.cid = e.cid AND i.sid = e.sid
                    WHERE e.cid >= {min_id} {date_clause}
    """.format(min_id=min_id, date_clause=date_clause))

    desc = c.description

    while True:
        row = c.fetchone()
        if not row:
            break
        yield {desc[i][0]: row[i] for i in range(len(row))}


# noinspection SqlNoDataSourceInspection,SqlDialectInspection
def get_net_event_history(net, interval, buckets):

    _legacy = {"ids": "vnet1", "ips": "vnet2"}

    if net.lower() in _legacy:
        net = _legacy[net.lower()]

    db = get_db(GATEWAY_DB_CONF[net])

    c = db.cursor()

    query = """
    SELECT src,
           dst,
           bucket,
           count(*) AS frequency
    FROM
      (SELECT *,
              floor((ts - UNIX_TIMESTAMP() + {interval}) / ({interval} / {buckets})) + 1 AS bucket
       FROM
         (SELECT e.cid,
                 inet_ntoa(ip_src) AS src,
                 inet_ntoa(ip_dst) AS dst,
                 unix_timestamp(timestamp) AS ts,
                 sig_id,
                 sig_name
          FROM event e
          INNER JOIN signature s ON e.signature = s.sig_id
          INNER JOIN iphdr i ON i.cid = e.cid AND i.sid = e.sid
          WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL {interval} second) 
    AS m) mb
    GROUP BY bucket,
             dst,
             src;
    """.format(interval=interval, buckets=buckets)

    c.execute(query)

    dsc = c.description
    print(dsc)

    while True:
        row = c.fetchone()
        if not row:
            break
        # import pdb
        # pdb.set_trace()
        yield {k[0]: row[i] for i, k in enumerate(dsc)}


def net_history(net=None, interval=600, buckets=10):

    if net is None:
        return list(get_net_event_history("ips", interval, buckets)) + \
           list(get_net_event_history("ids", interval, buckets))

    return list(get_net_event_history(net, interval, buckets))




