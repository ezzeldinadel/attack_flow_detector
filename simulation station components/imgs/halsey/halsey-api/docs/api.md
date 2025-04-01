
# Test working

URL: `/`

**Example Response**: 

```
Salam Donya
```

# VNet API

## Vnet get

URL: `/v1/vnet/get`

**Example Request**

```bash
curl localhost:8069/v1/vnet/get?host=00:00:00:00:00:04
```

**Example Response**

```
{"net": "vnet1"}
```

## Vnet toggle

Toggles VN (1 to 2, 2 to 3, ..., n-1 to n, n to 1)

URL: `/v1/vnet/toggle`

**Example Request**

```bash
curl localhost:8069/v1/vnet/toggle?host=00:00:00:00:00:04

```

**Example Response**

```
{"status": "OK"}
```

## Vnet set

URL: `/v1/vnet/set`

**Example Request**

```bash
curl "localhost:8069/v1/vnet/set?host=00:00:00:00:00:04&vnet=vnet1"
```

**Example Response**

```
{"status": "OK"}
```


## Vnet list

URL: `/v1/vnet/list`

**Example Request**

```bash
curl localhost:8069/v1/vnet/list
```

**Example Response**

```
[
  {
    "name": "vnet1",
    "security_level": 1,
    "gateway-ip": "172.17.0.3",
    "gateway-mac": "00:00:00:00:00:01"
  },
  {
    "name": "vnet2",
    "security_level": 2,
    "gateway-ip": "10.138.0.4",
    "gateway-mac": "00:00:00:00:00:02"
  }
]

```

## Vnet status

Tells where each host is

URL: `/v1/vnet/status`

**Example Request**

```bash
curl localhost:8069/vnet/status
```

**Example Response**

```
{
  "00:00:00:00:00:03": "vnet1",
  "00:00:00:00:00:04": "vnet1"
}
```




