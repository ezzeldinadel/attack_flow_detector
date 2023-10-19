import boto3
import botocore
from sagemaker import get_execution_role
import time

# import logging


def split_s3_path(s3_path):
    path_parts=s3_path.replace("s3://","").split("/")
    bucket=path_parts.pop(0)
    key="/".join(path_parts)
    return bucket, key

sm_client = boto3.client(service_name='sagemaker')
config = botocore.config.Config(read_timeout=900, connect_timeout = 900, tcp_keepalive=True)
runtime_sm_client = boto3.client(service_name='sagemaker-runtime', config = config)

s3_client = boto3.client("s3")
bucket = "technique-sagemaker-v1"

endpoint_name = 'seshat-correlation-gpu-endpoint'

import json
content_type = "application/json"

req_log_store = "request/fast.log"
req_json_store = "request/req.json"

# write input to log file
input = """02/14/2018-12:30:23.893882  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.83.224.201:24516 -> 172.31.64.111:445
02/14/2018-12:30:24.158368  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.83.224.201:24516 -> 172.31.64.111:445
02/14/2018-12:30:24.158368  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.83.224.201:24516 -> 172.31.64.111:445
02/14/2018-12:30:28.186213  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.83.224.201:24575 -> 172.31.64.111:445
02/14/2018-12:31:05.389409  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63668
02/14/2018-12:31:16.883358  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:60513
02/14/2018-12:31:54.918087  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59814
02/14/2018-12:31:55.443786  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59814
02/14/2018-12:31:35.121356  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57165
02/14/2018-12:31:05.777047  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:49326
02/14/2018-12:31:06.726320  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:49326
02/14/2018-12:30:51.176784  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59263
02/14/2018-12:32:19.410376  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51933
02/14/2018-12:31:03.778110  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57503
02/14/2018-12:31:43.424092  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64525
02/14/2018-12:32:29.074099  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55043
02/14/2018-12:32:29.583556  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55043
02/14/2018-12:32:30.505425  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55043
02/14/2018-12:33:06.506544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60152
02/14/2018-12:33:07.004525  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60152
02/14/2018-12:33:02.142099  [**] [1:2018959:4] ET POLICY PE EXE or DLL Windows file download HTTP [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 93.184.215.240:80 -> 172.31.64.111:49507
02/14/2018-12:34:15.392032  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60250
02/14/2018-12:33:24.436231  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64442
02/14/2018-12:35:07.582730  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50827
02/14/2018-12:35:08.313940  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50827
02/14/2018-12:35:09.688897  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50827
02/14/2018-12:35:14.250873  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55346
02/14/2018-12:34:31.126644  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57847
02/14/2018-12:33:36.138161  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57959
02/14/2018-12:36:09.952739  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53743
02/14/2018-12:35:49.103314  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:51248 -> 172.31.64.111:445
02/14/2018-12:34:53.472253  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64290
02/14/2018-12:35:49.279531  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.250.248.141:51248 -> 172.31.64.111:445
02/14/2018-12:35:49.279531  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.250.248.141:51248 -> 172.31.64.111:445
02/14/2018-12:35:45.299162  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59786
02/14/2018-12:35:49.279597  [**] [1:2025650:2] ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010 [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 172.31.64.111:445 -> 88.250.248.141:51248
02/14/2018-12:35:36.758157  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:61211 -> 172.31.64.111:445
02/14/2018-12:38:04.212029  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.12.91.138:54925 -> 172.31.64.111:445
02/14/2018-12:36:34.139230  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5101 -> 172.31.64.111:5060
02/14/2018-12:36:34.139230  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5101 -> 172.31.64.111:5060
02/14/2018-12:37:03.520284  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62619
02/14/2018-12:38:25.380175  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56507
02/14/2018-12:38:37.225294  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62487
02/14/2018-12:36:16.103959  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:62759
02/14/2018-12:38:09.897135  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53885
02/14/2018-12:37:21.424181  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56940
02/14/2018-12:36:03.289586  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.25:50794 -> 172.31.64.111:20754
02/14/2018-12:35:52.979854  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:51628 -> 172.31.64.111:445
02/14/2018-12:38:53.007549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53522
02/14/2018-12:39:47.058704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58044
02/14/2018-12:39:28.739030  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:51942 -> 172.31.64.111:445
02/14/2018-12:39:29.010668  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 49.248.214.82:51942 -> 172.31.64.111:445
02/14/2018-12:39:29.010668  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 49.248.214.82:51942 -> 172.31.64.111:445
02/14/2018-12:39:29.010737  [**] [1:2025650:2] ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010 [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 172.31.64.111:445 -> 49.248.214.82:51942
02/14/2018-12:36:19.802901  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 197.128.1.20:61030 -> 172.31.64.111:445
02/14/2018-12:41:55.526935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:58341
02/14/2018-12:36:19.990898  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 197.128.1.20:61030 -> 172.31.64.111:445
02/14/2018-12:36:19.990898  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 197.128.1.20:61030 -> 172.31.64.111:445
02/14/2018-12:42:32.046103  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51696
02/14/2018-12:36:28.539309  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52471
02/14/2018-12:43:01.824099  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63620
02/14/2018-12:36:23.748854  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 197.128.1.20:61448 -> 172.31.64.111:445
02/14/2018-12:43:06.264134  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.29.189.238:4566 -> 172.31.64.111:445
02/14/2018-12:35:20.068157  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56234
02/14/2018-12:39:58.355938  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 46.209.252.76:53578 -> 172.31.64.111:445
02/14/2018-12:39:37.532809  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:53724 -> 172.31.64.111:445
02/14/2018-12:39:58.578098  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 46.209.252.76:53578 -> 172.31.64.111:445
02/14/2018-12:39:58.578098  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 46.209.252.76:53578 -> 172.31.64.111:445
02/14/2018-12:43:02.514483  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.29.189.238:4157 -> 172.31.64.111:445
02/14/2018-12:46:10.567724  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49847
02/14/2018-12:45:31.780011  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54477
02/14/2018-12:45:57.790356  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55182
02/14/2018-12:45:43.026748  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:50942 -> 172.31.64.111:445
02/14/2018-12:43:02.665851  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.29.189.238:4157 -> 172.31.64.111:445
02/14/2018-12:43:02.665851  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.29.189.238:4157 -> 172.31.64.111:445
02/14/2018-12:47:48.482011  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.165.8.72:49685 -> 172.31.64.111:445
02/14/2018-12:46:42.440175  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49315
02/14/2018-12:45:43.278204  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.82.35.16:50942 -> 172.31.64.111:445
02/14/2018-12:45:43.278204  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.82.35.16:50942 -> 172.31.64.111:445
02/14/2018-12:45:43.278272  [**] [1:2025650:2] ET EXPLOIT ETERNALBLUE Probe Vulnerable System Response MS17-010 [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 172.31.64.111:445 -> 183.82.35.16:50942
02/14/2018-12:47:48.684060  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.165.8.72:49685 -> 172.31.64.111:445
02/14/2018-12:47:48.684060  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.165.8.72:49685 -> 172.31.64.111:445
02/14/2018-12:48:17.218673  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54478
02/14/2018-12:51:02.918627  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:57743
02/14/2018-12:38:58.053607  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:53369 -> 172.31.64.111:445
02/14/2018-12:34:10.749999  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61441
02/14/2018-12:35:41.816064  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:61729 -> 172.31.64.111:445
02/14/2018-12:40:12.807985  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54223
02/14/2018-12:39:33.155794  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:52832 -> 172.31.64.111:445
02/14/2018-12:47:50.238988  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60321
02/14/2018-12:48:15.222719  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58523
02/14/2018-12:51:42.084834  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63905
02/14/2018-12:37:05.983099  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 188.19.116.218:8939 -> 172.31.64.111:445
02/14/2018-12:38:54.174233  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:52999 -> 172.31.64.111:445
02/14/2018-12:48:00.086535  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57109
02/14/2018-12:36:52.623287  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64750
02/14/2018-12:35:00.248523  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:65186
02/14/2018-12:47:52.506466  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.165.8.72:50414 -> 172.31.64.111:445
02/14/2018-12:51:39.510708  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55251
02/14/2018-12:41:24.954386  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58524
02/14/2018-12:40:42.617633  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60796
02/14/2018-12:45:09.788113  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53814
02/14/2018-12:48:22.001366  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59166
02/14/2018-12:42:30.033190  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:53303
02/14/2018-12:35:32.362031  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:60772 -> 172.31.64.111:445
02/14/2018-12:35:32.630167  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.156.99.114:60772 -> 172.31.64.111:445
02/14/2018-12:35:32.630167  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.156.99.114:60772 -> 172.31.64.111:445
02/14/2018-12:35:59.421291  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.111:44473 -> 172.31.64.111:8555
02/14/2018-12:37:02.022562  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 188.19.116.218:8661 -> 172.31.64.111:445
02/14/2018-12:37:02.220814  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 188.19.116.218:8661 -> 172.31.64.111:445
02/14/2018-12:37:02.220814  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 188.19.116.218:8661 -> 172.31.64.111:445
02/14/2018-12:39:51.523838  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50873
02/14/2018-12:40:02.367433  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 46.209.252.76:53991 -> 172.31.64.111:445
02/14/2018-12:37:57.874661  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58187
02/14/2018-12:44:22.536969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59278
02/14/2018-12:35:56.807453  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:52014 -> 172.31.64.111:445
02/14/2018-12:36:20.021336  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65240
02/14/2018-12:50:21.786513  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.5.183.42:19053 -> 172.31.64.111:445
02/14/2018-12:50:22.098545  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.5.183.42:19053 -> 172.31.64.111:445
02/14/2018-12:50:22.098545  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.5.183.42:19053 -> 172.31.64.111:445
02/14/2018-12:44:46.043031  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51922
02/14/2018-12:41:45.799132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51023
02/14/2018-12:40:39.385866  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.206.115.242:20488 -> 172.31.64.111:445
02/14/2018-12:52:26.947360  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53245
02/14/2018-12:53:06.418030  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.154.103.133:60549 -> 172.31.64.111:445
02/14/2018-12:53:06.676148  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.154.103.133:60549 -> 172.31.64.111:445
02/14/2018-12:53:06.676148  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.154.103.133:60549 -> 172.31.64.111:445
02/14/2018-12:42:21.018102  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60848
02/14/2018-12:44:53.495830  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.126.167.154:54185 -> 172.31.64.111:445
02/14/2018-12:40:35.124237  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.206.115.242:20207 -> 172.31.64.111:445
02/14/2018-12:40:35.378536  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 49.206.115.242:20207 -> 172.31.64.111:445
02/14/2018-12:40:35.378536  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 49.206.115.242:20207 -> 172.31.64.111:445
02/14/2018-12:35:33.754532  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 200.63.22.173:59409 -> 172.31.64.111:445
02/14/2018-12:35:33.926702  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 200.63.22.173:59409 -> 172.31.64.111:445
02/14/2018-12:35:33.926702  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 200.63.22.173:59409 -> 172.31.64.111:445
02/14/2018-12:45:47.290075  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:51374 -> 172.31.64.111:445
02/14/2018-12:51:51.120777  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59481
02/14/2018-12:39:49.502149  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:62858
02/14/2018-12:45:51.572729  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:51810 -> 172.31.64.111:445
02/14/2018-12:50:26.250543  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.5.183.42:56390 -> 172.31.64.111:445
02/14/2018-12:51:29.596999  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:58526 -> 172.31.64.111:445
02/14/2018-12:53:36.909197  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63222
02/14/2018-12:37:59.797757  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.12.91.138:54463 -> 172.31.64.111:445
02/14/2018-12:38:00.082420  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.12.91.138:54463 -> 172.31.64.111:445
02/14/2018-12:38:00.082420  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.12.91.138:54463 -> 172.31.64.111:445
02/14/2018-12:43:34.565113  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65107
02/14/2018-12:51:23.646398  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:58058 -> 172.31.64.111:445
02/14/2018-12:38:44.688733  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56766
02/14/2018-12:41:04.645937  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55058
02/14/2018-12:50:32.152394  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61575
02/14/2018-12:44:12.901753  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:59663
02/14/2018-12:52:07.487580  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:2988
02/14/2018-12:51:54.112302  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:62206
02/14/2018-12:35:37.583398  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 200.63.22.173:59517 -> 172.31.64.111:445
02/14/2018-12:51:54.460201  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:62206
02/14/2018-12:43:06.724868  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57892
02/14/2018-12:44:53.513043  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58849
02/14/2018-12:49:24.159828  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60342
02/14/2018-12:47:05.526474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56454
02/14/2018-12:49:03.239911  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54779
02/14/2018-12:48:31.178176  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:58635 -> 172.31.64.111:3389
02/14/2018-12:48:33.925343  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:58635 -> 172.31.64.111:3389
02/14/2018-12:48:40.224889  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:58635
02/14/2018-12:53:28.440316  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62504
02/14/2018-12:49:49.415071  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64368
02/14/2018-12:50:08.077050  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:65398
02/14/2018-12:52:51.593728  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49627
02/14/2018-12:44:21.720598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58959
02/14/2018-12:53:10.710648  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.154.103.133:61066 -> 172.31.64.111:445
02/14/2018-12:44:49.735720  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.126.167.154:53794 -> 172.31.64.111:445
02/14/2018-12:44:49.882544  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.126.167.154:53794 -> 172.31.64.111:445
02/14/2018-12:44:49.882544  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.126.167.154:53794 -> 172.31.64.111:445
02/14/2018-12:53:46.665562  [**] [1:2018959:4] ET POLICY PE EXE or DLL Windows file download HTTP [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 93.184.215.240:80 -> 172.31.64.111:49600
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:65186
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51023
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55346
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59278
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57847
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59263
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58044
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:59663
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50873
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51696
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56766
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56234
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57959
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60796
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51922
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62487
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57503
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:53303
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:62759
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59786
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64442
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54477
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:60513
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54223
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60848
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64290
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53522
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57892
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50827
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51933
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58849
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63668
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53814
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58524
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55058
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57165
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63620
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55043
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60250
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64525
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:58187
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58959
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65240
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65107
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53743
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:58341
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:62858
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56940
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56507
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62619
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:49326
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61441
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64750
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52471
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53885
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59814
02/14/2018-12:47:48.913243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60152
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54779
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59166
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54478
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61575
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64368
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49315
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58523
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:57743
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55251
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55182
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49847
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60342
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63905
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60321
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56454
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57109
02/14/2018-12:53:48.727864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:65398
02/14/2018-12:54:00.997172  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51658
02/14/2018-12:54:26.401516  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:63883 -> 172.31.64.111:445
02/14/2018-12:54:30.262784  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:64266 -> 172.31.64.111:445
02/14/2018-12:55:20.428300  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59794
02/14/2018-12:55:21.831418  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:61284 -> 172.31.64.111:445
02/14/2018-12:54:43.964228  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56588
02/14/2018-12:55:17.787921  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 14.142.181.2:63172 -> 172.31.64.111:445
02/14/2018-12:55:54.137059  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49690
02/14/2018-12:55:17.396649  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53388
02/14/2018-12:55:13.499888  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 14.142.181.2:62761 -> 172.31.64.111:445
02/14/2018-12:56:29.447899  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55391
02/14/2018-12:55:10.981924  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53965
02/14/2018-12:56:19.805353  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55634
02/14/2018-12:56:34.756264  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60927
02/14/2018-12:55:23.407004  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.95.204.241:61607 -> 172.31.64.111:445
02/14/2018-12:55:19.458140  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.95.204.241:60811 -> 172.31.64.111:445
02/14/2018-12:55:30.744383  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:63038 -> 172.31.64.111:445
02/14/2018-12:57:10.125110  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:58857
02/14/2018-12:55:13.755468  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 14.142.181.2:62761 -> 172.31.64.111:445
02/14/2018-12:55:19.675988  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.95.204.241:60811 -> 172.31.64.111:445
02/14/2018-12:55:19.675988  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.95.204.241:60811 -> 172.31.64.111:445
02/14/2018-12:55:13.755468  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 14.142.181.2:62761 -> 172.31.64.111:445
02/14/2018-12:56:37.248409  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:58680
02/14/2018-12:57:02.108123  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.16.136.62:62250 -> 172.31.64.111:445
02/14/2018-12:57:05.875926  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60639
02/14/2018-12:55:35.089854  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:63915 -> 172.31.64.111:445
02/14/2018-12:54:47.854070  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:63504
02/14/2018-12:55:57.074943  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61081
02/14/2018-12:56:57.697451  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.16.136.62:61805 -> 172.31.64.111:445
02/14/2018-12:56:57.977570  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.16.136.62:61805 -> 172.31.64.111:445
02/14/2018-12:56:57.977570  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.16.136.62:61805 -> 172.31.64.111:445
02/14/2018-12:57:18.089346  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56588
02/14/2018-12:57:18.090348  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:63504
02/14/2018-12:57:18.857049  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62504
02/14/2018-12:57:19.051358  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53245
02/14/2018-12:57:18.954993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51658
02/14/2018-12:57:19.218909  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49627
02/14/2018-12:57:29.549625  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57742
02/14/2018-12:57:19.459265  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59481
02/14/2018-12:57:20.290841  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:2988
02/14/2018-12:57:20.291288  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53965
02/14/2018-12:57:33.836603  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63881
02/14/2018-12:57:19.067727  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:62206
02/14/2018-12:57:19.067727  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63222
02/14/2018-12:57:25.447105  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:59794
02/14/2018-12:57:25.447105  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53388
02/14/2018-12:57:53.130154  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61300
02/14/2018-12:58:13.913384  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51345
02/14/2018-12:58:19.224426  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53273
02/14/2018-12:58:40.680899  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60378
02/14/2018-12:58:41.352653  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:58236
02/14/2018-12:58:54.420156  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:60103
02/14/2018-12:58:54.865005  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51520
02/14/2018-12:59:50.817935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62641
02/14/2018-13:00:18.538550  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51924
02/14/2018-13:00:20.537073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53971
02/14/2018-13:00:35.240466  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.95.99.203:61377 -> 172.31.64.111:445
02/14/2018-13:00:31.435798  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.95.99.203:61001 -> 172.31.64.111:445
02/14/2018-13:00:43.732361  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58765
02/14/2018-12:58:08.905924  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61081
02/14/2018-13:00:31.598599  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.95.99.203:61001 -> 172.31.64.111:445
02/14/2018-13:00:31.598599  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.95.99.203:61001 -> 172.31.64.111:445
02/14/2018-13:00:57.562391  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.3.104.118:60100 -> 172.31.64.111:445
02/14/2018-13:01:01.687672  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.3.104.118:60520 -> 172.31.64.111:445
02/14/2018-13:00:58.741539  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63763
02/14/2018-13:01:21.719863  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60115
02/14/2018-13:01:28.781729  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:63794 -> 172.31.64.111:445
02/14/2018-13:00:57.816407  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.3.104.118:60100 -> 172.31.64.111:445
02/14/2018-13:00:57.816407  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.3.104.118:60100 -> 172.31.64.111:445
02/14/2018-13:01:13.379676  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53326
02/14/2018-12:58:08.905924  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49690
02/14/2018-13:02:16.180756  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55663
02/14/2018-13:02:04.418892  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63822
02/14/2018-13:02:16.756844  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55663
02/14/2018-13:02:33.716907  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49621
02/14/2018-13:03:10.038932  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50355
02/14/2018-13:02:32.053823  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51637
02/14/2018-13:01:54.272637  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55156
02/14/2018-13:03:36.276726  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59235
02/14/2018-13:02:25.173730  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:61573
02/14/2018-13:04:00.836044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61181
02/14/2018-13:04:03.847846  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61181
02/14/2018-13:04:15.380740  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63789
02/14/2018-13:02:36.791903  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 218.87.194.83:60666 -> 172.31.64.111:445
02/14/2018-13:04:43.317438  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50075
02/14/2018-13:01:33.060708  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:64243 -> 172.31.64.111:445
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55634
02/14/2018-13:04:23.388968  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56874
02/14/2018-13:05:20.675245  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60790
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55391
02/14/2018-13:05:54.867935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:61871
02/14/2018-13:05:49.796037  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56949
02/14/2018-13:05:50.522630  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:56181
02/14/2018-13:05:33.680634  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50309
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60927
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:58857
02/14/2018-13:06:01.582568  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61904
02/14/2018-13:05:58.521055  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55871
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60639
02/14/2018-12:59:12.231066  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:58680
02/14/2018-13:06:15.823462  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64114
02/14/2018-13:06:16.498232  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 179.52.56.136:59494 -> 172.31.64.111:445
02/14/2018-13:06:16.579278  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 179.52.56.136:59494 -> 172.31.64.111:445
02/14/2018-13:06:16.579278  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 179.52.56.136:59494 -> 172.31.64.111:445
02/14/2018-13:06:25.756493  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58051
02/14/2018-13:00:30.947260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51345
02/14/2018-13:00:30.947260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57742
02/14/2018-13:00:30.947260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53273
02/14/2018-13:00:30.947260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63881
02/14/2018-13:06:41.971999  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63515
02/14/2018-13:07:30.749340  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56128
02/14/2018-13:07:36.147418  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:57991 -> 172.31.64.111:445
02/14/2018-13:07:40.885259  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:58464 -> 172.31.64.111:445
02/14/2018-13:08:01.783048  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54989
02/14/2018-13:07:34.791993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53492
02/14/2018-13:08:36.240549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54311
02/14/2018-13:08:38.984816  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59677
02/14/2018-13:06:19.879767  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 179.52.56.136:18571 -> 172.31.64.111:445
02/14/2018-13:09:01.175558  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62341
02/14/2018-13:09:04.935675  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57069
02/14/2018-13:09:05.777643  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57069
02/14/2018-13:08:52.401400  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58828
02/14/2018-13:09:07.371373  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57069
02/14/2018-13:09:24.821369  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62169
02/14/2018-13:08:26.417788  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54219
02/14/2018-13:09:30.083479  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:57745
02/14/2018-13:09:30.185011  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64740
02/14/2018-13:09:51.342534  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62225
02/14/2018-13:10:10.532977  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60391
02/14/2018-13:09:35.309669  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49282
02/14/2018-13:09:41.654303  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51330
02/14/2018-13:10:09.486296  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.33.237.86:53390 -> 172.31.64.111:445
02/14/2018-13:10:09.613836  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.33.237.86:53390 -> 172.31.64.111:445
02/14/2018-13:10:09.613836  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.33.237.86:53390 -> 172.31.64.111:445
02/14/2018-13:10:24.408101  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:61425 -> 172.31.64.111:445
02/14/2018-13:10:20.516498  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:61027 -> 172.31.64.111:445
02/14/2018-13:10:47.285591  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49195
02/14/2018-13:10:36.875137  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55019
02/14/2018-13:10:58.877886  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64786
02/14/2018-13:10:13.189410  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.33.237.86:53767 -> 172.31.64.111:445
02/14/2018-13:11:33.823264  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60523
02/14/2018-13:02:32.017439  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64593
02/14/2018-13:11:34.288823  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:59723 -> 172.31.64.111:445
02/14/2018-13:11:46.881589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53538
02/14/2018-13:11:41.496773  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53095
02/14/2018-13:02:32.616364  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 218.87.194.83:59852 -> 172.31.64.111:445
02/14/2018-13:11:09.416250  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61366
02/14/2018-13:11:53.389045  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63618
02/14/2018-13:02:32.826899  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 218.87.194.83:59852 -> 172.31.64.111:445
02/14/2018-13:11:57.114589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61461
02/14/2018-13:02:32.826899  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 218.87.194.83:59852 -> 172.31.64.111:445
02/14/2018-13:12:24.907119  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55376
02/14/2018-13:12:38.654029  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49374
02/14/2018-13:02:35.021996  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64593
02/14/2018-13:11:38.629514  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:60606 -> 172.31.64.111:445
02/14/2018-13:12:54.632501  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62463
02/14/2018-13:13:16.794778  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:52973
02/14/2018-13:12:58.926609  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61264
02/14/2018-13:00:30.947260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61300
02/14/2018-13:02:36.899060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60378
02/14/2018-13:13:31.022014  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60333
02/14/2018-13:13:33.850932  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54240
02/14/2018-13:14:04.713125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59244
02/14/2018-13:08:04.455750  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:60103
02/14/2018-13:02:35.544246  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51924
02/14/2018-13:08:04.455750  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62641
02/14/2018-13:08:04.455750  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53971
02/14/2018-13:08:04.455750  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51520
02/14/2018-13:08:13.074350  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:58236
02/14/2018-13:15:10.224097  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57293
02/14/2018-13:15:20.015502  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51208
02/14/2018-13:15:33.226965  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:56159
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:61573
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63763
02/14/2018-13:16:23.796985  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62749
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58051
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58765
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63789
02/14/2018-13:17:20.936806  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53906
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50075
02/14/2018-13:17:39.499938  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:58797
02/14/2018-13:17:27.180234  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:61619 -> 172.31.64.111:445
02/14/2018-13:17:13.178583  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:52573
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49621
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63822
02/14/2018-13:17:22.863817  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:61188 -> 172.31.64.111:445
02/14/2018-13:13:51.273783  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51637
02/14/2018-13:16:15.493122  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55513
02/14/2018-13:13:51.274273  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56128
02/14/2018-13:15:14.038823  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63029
02/14/2018-13:13:51.274640  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63515
02/14/2018-13:13:51.274142  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60115
02/14/2018-13:17:58.867106  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 37.239.255.254:61160 -> 172.31.64.111:445
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55871
02/14/2018-13:15:57.855335  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50781
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:61871
02/14/2018-13:13:51.274601  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61181
02/14/2018-13:17:54.695625  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 37.239.255.254:60662 -> 172.31.64.111:445
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56949
02/14/2018-13:13:51.273783  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:56181
02/14/2018-13:13:51.273783  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50355
02/14/2018-13:18:23.344267  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51070
02/14/2018-13:19:29.047882  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 203.130.231.173:62007 -> 172.31.64.111:445
02/14/2018-13:17:54.931855  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 37.239.255.254:60662 -> 172.31.64.111:445
02/14/2018-13:17:54.931855  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 37.239.255.254:60662 -> 172.31.64.111:445
02/14/2018-13:19:17.802740  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:59913
02/14/2018-13:18:40.669667  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62637
02/14/2018-13:11:12.045213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60790
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53492
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50309
02/14/2018-13:13:51.274474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64114
02/14/2018-13:19:24.594392  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 203.130.231.173:61580 -> 172.31.64.111:445
02/14/2018-13:18:58.439051  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49294
02/14/2018-13:18:27.737091  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51962
02/14/2018-13:19:24.885644  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 203.130.231.173:61580 -> 172.31.64.111:445
02/14/2018-13:19:24.885644  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 203.130.231.173:61580 -> 172.31.64.111:445
02/14/2018-13:17:38.520113  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50555
02/14/2018-13:17:09.306192  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58445
02/14/2018-13:11:41.694764  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55156
02/14/2018-13:19:33.214175  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50451
02/14/2018-13:13:51.274474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53326
02/14/2018-13:13:51.274474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64593
02/14/2018-13:19:31.740540  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49946
02/14/2018-13:19:40.579427  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50728
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56874
02/14/2018-13:13:51.274640  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55663
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59235
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61904
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54989
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:52973
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55376
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60523
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59677
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60333
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62341
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57069
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55019
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49282
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53538
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58828
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63618
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61366
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64740
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62225
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54219
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53095
02/14/2018-13:17:13.370867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61461
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54311
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59244
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62463
02/14/2018-13:17:13.370867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61264
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51330
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60391
02/14/2018-13:19:46.212308  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 79.53.43.134:54138 -> 172.31.64.111:445
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49195
02/14/2018-13:19:46.389264  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 79.53.43.134:54138 -> 172.31.64.111:445
02/14/2018-13:19:46.389264  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 79.53.43.134:54138 -> 172.31.64.111:445
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64786
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62169
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54240
02/14/2018-13:16:17.362073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49374
02/14/2018-13:17:13.370867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:57745
02/14/2018-13:19:50.022324  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 79.53.43.134:54536 -> 172.31.64.111:445
02/14/2018-13:19:51.663167  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.100.68.101:60890 -> 172.31.64.111:445
02/14/2018-13:19:51.848665  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.100.68.101:60890 -> 172.31.64.111:445
02/14/2018-13:19:51.848665  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.100.68.101:60890 -> 172.31.64.111:445
02/14/2018-13:20:17.547023  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53448
02/14/2018-13:21:45.832728  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 58.56.161.30:54840 -> 172.31.64.111:22
02/14/2018-13:19:50.409553  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52105
02/14/2018-13:22:03.069584  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:56706
02/14/2018-13:22:03.833170  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59817
02/14/2018-13:20:39.443012  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64797
02/14/2018-13:19:55.579880  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.100.68.101:50827 -> 172.31.64.111:445
02/14/2018-13:20:53.688805  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:41184
02/14/2018-13:22:47.525048  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62693
02/14/2018-13:23:06.957524  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51795
02/14/2018-13:23:17.547935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55350
02/14/2018-13:21:51.783694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49461
02/14/2018-13:23:18.940621  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:57175
02/14/2018-13:23:46.150543  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.239.160.145:59472 -> 172.31.64.111:445
02/14/2018-13:23:46.379688  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.239.160.145:59472 -> 172.31.64.111:445
02/14/2018-13:23:46.379688  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.239.160.145:59472 -> 172.31.64.111:445
02/14/2018-13:23:54.422754  [**] [1:2400007:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 8 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 123.249.27.171:17768 -> 172.31.64.111:60001
02/14/2018-13:24:04.294927  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 217.118.95.84:6836 -> 172.31.64.111:445
02/14/2018-13:24:00.290275  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 217.118.95.84:6835 -> 172.31.64.111:445
02/14/2018-13:24:00.476828  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 217.118.95.84:6835 -> 172.31.64.111:445
02/14/2018-13:24:00.476828  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 217.118.95.84:6835 -> 172.31.64.111:445
02/14/2018-13:25:01.212277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54111
02/14/2018-13:26:16.865472  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61845
02/14/2018-13:27:01.144943  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51859
02/14/2018-13:23:29.724413  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:56360 -> 172.31.64.111:445
02/14/2018-13:27:28.441510  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:55140 -> 172.31.64.111:445
02/14/2018-13:28:24.597398  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49344
02/14/2018-13:28:36.001233  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58897
02/14/2018-13:20:10.898912  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5097 -> 172.31.64.111:5060
02/14/2018-13:20:10.898912  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5097 -> 172.31.64.111:5060
02/14/2018-13:22:37.578232  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63764
02/14/2018-13:29:06.251477  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.86.78:63411 -> 172.31.64.111:445
02/14/2018-13:29:06.430853  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.156.86.78:63411 -> 172.31.64.111:445
02/14/2018-13:21:46.564135  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58128
02/14/2018-13:29:06.430853  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 212.156.86.78:63411 -> 172.31.64.111:445
02/14/2018-13:21:13.341574  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56732
02/14/2018-13:26:33.007095  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:59202 -> 172.31.64.111:445
02/14/2018-13:26:54.659899  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63587
02/14/2018-13:24:27.410023  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54622
02/14/2018-13:29:50.931831  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53554
02/14/2018-13:27:03.038190  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:61265
02/14/2018-13:30:40.929270  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65373
02/14/2018-13:23:33.963934  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.99.114:56791 -> 172.31.64.111:445
02/14/2018-13:25:25.103843  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64305
02/14/2018-13:31:45.341041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50773
02/14/2018-13:20:17.414688  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51492
02/14/2018-13:20:18.135538  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51492
02/14/2018-13:24:32.168984  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58741
02/14/2018-13:33:39.619974  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:60087 -> 172.31.64.111:445
02/14/2018-13:33:56.820743  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64125
02/14/2018-13:31:21.827047  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:57481
02/14/2018-13:32:17.540090  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59298
02/14/2018-13:27:48.297035  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63527
02/14/2018-13:33:34.798015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57990
02/14/2018-13:29:57.136591  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61477
02/14/2018-13:23:24.254888  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63312
02/14/2018-13:33:35.313921  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.82.35.16:59658 -> 172.31.64.111:445
02/14/2018-13:26:37.021338  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.250.248.141:59614 -> 172.31.64.111:445
02/14/2018-13:23:50.230324  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.239.160.145:59902 -> 172.31.64.111:445
02/14/2018-13:28:42.043600  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 151.106.17.146:5433 -> 172.31.64.111:5060
02/14/2018-13:28:42.043600  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 151.106.17.146:5433 -> 172.31.64.111:5060
02/14/2018-13:32:37.122424  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57206
02/14/2018-13:20:47.900963  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56538
02/14/2018-13:34:58.845168  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:55734
02/14/2018-13:35:09.445247  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59548
02/14/2018-13:35:10.195748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:65263
02/14/2018-13:25:51.711550  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62941
02/14/2018-13:35:24.143440  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65208
02/14/2018-13:36:30.936459  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:60718
02/14/2018-13:36:27.393048  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63558
02/14/2018-13:28:05.939492  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52700
02/14/2018-13:28:25.882228  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52083
02/14/2018-13:19:46.916146  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:58797
02/14/2018-13:37:54.202487  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:55773 -> 172.31.64.111:3389
02/14/2018-13:37:46.684609  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51690
02/14/2018-13:27:32.999278  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 49.248.214.82:56034 -> 172.31.64.111:445
02/14/2018-13:37:57.125432  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:55773 -> 172.31.64.111:3389
02/14/2018-13:38:09.885579  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 93.80.29.108:63548 -> 172.31.64.111:445
02/14/2018-13:38:03.163006  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:55773
02/14/2018-13:38:10.018337  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 93.80.29.108:63548 -> 172.31.64.111:445
02/14/2018-13:38:10.018337  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 93.80.29.108:63548 -> 172.31.64.111:445
02/14/2018-13:35:10.268762  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54178
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53906
02/14/2018-13:38:13.555145  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 93.80.29.108:63917 -> 172.31.64.111:445
02/14/2018-13:39:48.615137  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.84.224.95:5290 -> 172.31.64.111:445
02/14/2018-13:40:14.668375  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:50616
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51208
02/14/2018-13:39:49.237501  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.84.224.95:5290 -> 172.31.64.111:445
02/14/2018-13:39:49.237501  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.84.224.95:5290 -> 172.31.64.111:445
02/14/2018-13:38:13.708458  [**] [1:2402000:5577] ET DROP Dshield Block Listed Source group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 80.82.77.33:58022 -> 172.31.64.111:25105
02/14/2018-13:38:13.708458  [**] [1:2403374:58049] ET CINS Active Threat Intelligence Poor Reputation IP group 75 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 80.82.77.33:58022 -> 172.31.64.111:25105
02/14/2018-13:34:25.464733  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:3522
02/14/2018-13:40:53.042365  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54133
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:62749
02/14/2018-13:44:14.679931  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.232.104.21:55209 -> 172.31.64.111:445
02/14/2018-13:35:42.210654  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5103 -> 172.31.64.111:5060
02/14/2018-13:35:42.210654  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5103 -> 172.31.64.111:5060
02/14/2018-13:44:14.872861  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.232.104.21:55209 -> 172.31.64.111:445
02/14/2018-13:44:14.872861  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.232.104.21:55209 -> 172.31.64.111:445
02/14/2018-13:40:52.378309  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54153
02/14/2018-13:44:17.516080  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51761
02/14/2018-13:44:18.654275  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.232.104.21:55597 -> 172.31.64.111:445
02/14/2018-13:45:10.437592  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61306
02/14/2018-13:45:11.221468  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62986
02/14/2018-13:45:38.206989  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59915
02/14/2018-13:37:13.366878  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56057
02/14/2018-13:37:29.192242  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50687
02/14/2018-13:46:27.735034  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50422
02/14/2018-13:36:34.486950  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50931
02/14/2018-13:48:09.122734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63022
02/14/2018-13:44:31.876547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:52966
02/14/2018-13:48:13.814239  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50147
02/14/2018-13:19:46.917167  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50781
02/14/2018-13:28:18.168485  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51944
02/14/2018-13:46:22.913266  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59424
02/14/2018-13:21:58.369278  [**] [1:2400019:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 20 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 191.101.167.235:49866 -> 172.31.64.111:8545
02/14/2018-13:38:40.964631  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53180
02/14/2018-13:49:02.904027  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:53320
02/14/2018-13:39:53.949154  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.84.224.95:3821 -> 172.31.64.111:445
02/14/2018-13:49:39.781087  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:50251
02/14/2018-13:47:43.762662  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 58.187.70.92:51745 -> 172.31.64.111:445
02/14/2018-13:47:44.019882  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 58.187.70.92:51745 -> 172.31.64.111:445
02/14/2018-13:47:44.019882  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 58.187.70.92:51745 -> 172.31.64.111:445
02/14/2018-13:37:27.032063  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64383
02/14/2018-13:38:25.711519  [**] [1:2400019:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 20 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 191.101.167.246:50512 -> 172.31.64.111:3370
02/14/2018-13:42:43.115058  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61366
02/14/2018-13:45:44.825959  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51406
02/14/2018-13:49:50.591202  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52067
02/14/2018-13:48:15.237660  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50262
02/14/2018-13:41:43.300355  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63140
02/14/2018-13:47:56.492269  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:65118
02/14/2018-13:33:35.251588  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62540
02/14/2018-13:43:00.684185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49667
02/14/2018-13:29:55.071033  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59925
02/14/2018-13:44:22.245546  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 181.214.87.248:53768 -> 172.31.64.111:3389
02/14/2018-13:30:44.921160  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55564
02/14/2018-13:29:10.165330  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 212.156.86.78:63817 -> 172.31.64.111:445
02/14/2018-13:39:04.644052  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:58470
02/14/2018-13:39:30.374564  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53675
02/14/2018-13:19:53.869743  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63032
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58445
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50555
02/14/2018-13:27:13.502340  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52856
02/14/2018-13:49:18.645508  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60188
02/14/2018-13:44:26.221812  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64880
02/14/2018-13:44:33.429295  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52213
02/14/2018-13:44:59.676912  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 65.132.24.137:52826 -> 172.31.64.111:445
02/14/2018-13:44:59.724700  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 65.132.24.137:52826 -> 172.31.64.111:445
02/14/2018-13:44:59.724700  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 65.132.24.137:52826 -> 172.31.64.111:445
02/14/2018-13:39:05.486972  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55509
02/14/2018-13:28:37.235200  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64030
02/14/2018-13:37:59.142796  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:52531
02/14/2018-13:32:51.699837  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60987
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63029
02/14/2018-13:38:26.418645  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:64860
02/14/2018-13:33:49.056599  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:52355
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57293
02/14/2018-13:31:17.274694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49910
02/14/2018-13:23:10.655710  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58227
02/14/2018-13:44:38.514775  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64121
02/14/2018-13:43:41.836765  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53501
02/14/2018-13:30:25.870867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63857
02/14/2018-13:32:32.541704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51571
02/14/2018-13:33:15.989040  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:51608
02/14/2018-13:45:11.846876  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64403
02/14/2018-13:48:18.891935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61881
02/14/2018-13:45:31.746000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52701
02/14/2018-13:33:51.028561  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55501
02/14/2018-13:46:37.569462  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64297
02/14/2018-13:40:11.492993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53997
02/14/2018-13:45:03.240453  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 65.132.24.137:10538 -> 172.31.64.111:445
02/14/2018-13:46:59.417789  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49268
02/14/2018-13:40:57.128540  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64635
02/14/2018-13:47:42.073915  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59862
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:52573
02/14/2018-13:47:19.740218  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 217.79.190.13:6187 -> 172.31.64.111:5060
02/14/2018-13:47:19.740218  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 217.79.190.13:6187 -> 172.31.64.111:5060
02/14/2018-13:40:26.110965  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60436
02/14/2018-13:41:05.408286  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58580
02/14/2018-13:41:08.416180  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58580
02/14/2018-13:47:35.834615  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58298
02/14/2018-13:47:36.359439  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58298
02/14/2018-13:50:13.249652  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:2448
02/14/2018-13:42:15.515836  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54250
02/14/2018-13:43:23.031925  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54985
02/14/2018-13:43:26.037666  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54985
02/14/2018-13:35:52.463854  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49989
02/14/2018-13:45:55.286116  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50621
02/14/2018-13:45:55.830763  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50621
02/14/2018-13:48:26.661987  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:50146
02/14/2018-13:48:40.744672  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60133
02/14/2018-13:34:22.856731  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63975
02/14/2018-13:37:12.582725  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51776
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55513
02/14/2018-13:39:33.811777  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55968
02/14/2018-13:19:47.019072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:56159
02/14/2018-13:49:09.165834  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:50463
02/14/2018-13:39:02.793297  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63271
02/14/2018-13:48:47.053633  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56306
02/14/2018-13:41:40.343117  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53094
02/14/2018-13:41:31.210579  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54154
02/14/2018-13:47:48.042183  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 58.187.70.92:52189 -> 172.31.64.111:445
02/14/2018-13:43:02.165174  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.111:44473 -> 172.31.64.111:19191
02/14/2018-13:50:02.015087  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57474
02/14/2018-13:46:40.264083  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56665
02/14/2018-13:42:15.930505  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54055
02/14/2018-13:45:52.819740  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57078
02/14/2018-13:50:04.160471  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:53662
02/14/2018-13:47:32.980322  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:64364
02/14/2018-13:48:30.698327  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:56319
02/14/2018-13:47:39.111650  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:54641
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50451
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49461
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:60718
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:55734
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63032
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54250
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55350
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:57175
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63587
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58128
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54622
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65208
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64125
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53997
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54133
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62637
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50687
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52105
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:65263
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49294
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63527
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53554
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63312
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:52355
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:59913
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63271
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63140
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63975
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61845
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61366
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49667
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:56732
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52083
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54153
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:41184
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50773
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56057
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49910
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51690
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52856
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54055
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54154
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64030
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53501
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60987
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51492
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51859
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:54111
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:56706
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60436
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51962
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53448
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51944
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53094
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55564
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:63857
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49989
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:3522
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:51608
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51776
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:61265
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51571
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58227
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57990
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55968
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51070
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59298
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64635
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:57481
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65373
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:52531
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51795
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58897
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62941
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:59817
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54178
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63558
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64383
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55501
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64305
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54985
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59548
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52700
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63764
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56538
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:64860
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58580
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59925
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58741
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49946
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49344
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:50616
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57206
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64797
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55509
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53180
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50931
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:53675
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62693
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:62540
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:50728
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:58470
02/14/2018-13:45:57.670642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61477
02/14/2018-13:50:38.415055  [**] [1:2001972:20] ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) [**] [Classification: Detection of a Network Scan] [Priority: 3] {TCP} 5.101.40.105:57040 -> 172.31.64.111:3389
02/14/2018-13:50:27.768460  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60249
02/14/2018-13:51:17.909334  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55234
02/14/2018-13:51:26.547217  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:65350
02/14/2018-13:50:53.775818  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64214
02/14/2018-13:50:38.529310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:57040
02/14/2018-13:52:59.270107  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52254
02/14/2018-13:51:56.801605  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59822
02/14/2018-13:51:52.694205  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64683
02/14/2018-13:52:24.996620  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64697
02/14/2018-13:53:42.715013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55521
02/14/2018-13:53:08.583236  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.12.89.66:53153 -> 172.31.64.111:445
02/14/2018-13:53:08.820123  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.12.89.66:53153 -> 172.31.64.111:445
02/14/2018-13:53:08.820123  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.12.89.66:53153 -> 172.31.64.111:445
02/14/2018-13:54:01.165432  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58197
02/14/2018-13:53:12.768248  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.12.89.66:57313 -> 172.31.64.111:445
02/14/2018-13:50:21.683589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:50422
02/14/2018-13:50:21.683589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56665
02/14/2018-13:50:21.683589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62986
02/14/2018-13:50:21.683589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58298
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50262
02/14/2018-13:55:33.294901  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62730
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59915
02/14/2018-13:54:43.911621  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65043
02/14/2018-13:50:55.924322  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:65118
02/14/2018-13:50:55.924322  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:64880
02/14/2018-13:55:12.393116  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:56088
02/14/2018-13:56:10.946055  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64802
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:54641
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64403
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61306
02/14/2018-13:56:03.313398  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54095
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59862
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64121
02/14/2018-13:51:33.337848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52213
02/14/2018-13:54:57.858212  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:49208
02/14/2018-13:57:04.592632  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60131
02/14/2018-13:57:23.429072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53570
02/14/2018-13:58:05.806142  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49637
02/14/2018-13:57:25.383670  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:56212
02/14/2018-13:51:33.337848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:63022
02/14/2018-13:51:15.178825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52701
02/14/2018-13:52:50.804747  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50621
02/14/2018-13:58:27.274476  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62813
02/14/2018-13:58:24.806331  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.193:65533 -> 172.31.64.111:5018
02/14/2018-13:53:07.818890  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61881
02/14/2018-13:58:55.437252  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64284
02/14/2018-13:55:02.433194  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64547
02/14/2018-13:59:02.741584  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53041
02/14/2018-13:59:13.319228  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60775
02/14/2018-13:53:07.818890  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51761
02/14/2018-13:51:33.337848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:51406
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59424
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:64364
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:49268
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64297
02/14/2018-13:59:07.071910  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55883
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:52966
02/14/2018-13:59:44.502685  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 60.249.188.117:62475 -> 172.31.64.111:445
02/14/2018-13:58:28.847554  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:49432
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57078
02/14/2018-14:00:08.343512  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62502
02/14/2018-13:59:40.447462  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 60.249.188.117:52060 -> 172.31.64.111:445
02/14/2018-13:59:40.648888  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 60.249.188.117:52060 -> 172.31.64.111:445
02/14/2018-13:59:40.648888  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 60.249.188.117:52060 -> 172.31.64.111:445
02/14/2018-14:01:09.272525  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52831
02/14/2018-14:01:20.835760  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58400
02/14/2018-14:01:03.106192  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51610
02/14/2018-13:54:17.048547  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:50147
02/14/2018-14:01:58.995732  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:50814
02/14/2018-14:00:37.819961  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:53553
02/14/2018-14:02:10.164671  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59538
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56306
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:57040
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:65350
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:2448
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52254
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:60188
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64683
02/14/2018-14:02:43.957913  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:53335
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:53662
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:50251
02/14/2018-14:02:24.384418  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 110.136.55.165:49908 -> 172.31.64.111:445
02/14/2018-14:02:52.808678  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58812
02/14/2018-14:03:11.273594  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50330
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57474
02/14/2018-14:02:44.443413  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.25:50794 -> 172.31.64.111:20794
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60133
02/14/2018-14:02:28.708757  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 110.136.55.165:50351 -> 172.31.64.111:445
02/14/2018-14:02:24.649353  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 110.136.55.165:49908 -> 172.31.64.111:445
02/14/2018-14:02:24.649353  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 110.136.55.165:49908 -> 172.31.64.111:445
02/14/2018-14:02:50.624651  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 125.209.80.114:58428 -> 172.31.64.111:445
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:50146
02/14/2018-14:02:55.057847  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 125.209.80.114:58891 -> 172.31.64.111:445
02/14/2018-14:03:20.539160  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 113.160.181.58:59042 -> 172.31.64.111:445
02/14/2018-14:02:56.214532  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:63424
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.101.40.105:55234
02/14/2018-14:02:50.916722  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 125.209.80.114:58428 -> 172.31.64.111:445
02/14/2018-14:03:16.223946  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 113.160.181.58:58523 -> 172.31.64.111:445
02/14/2018-13:59:42.059432  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60249
02/14/2018-14:03:30.017896  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:47979
02/14/2018-14:02:50.916722  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 125.209.80.114:58428 -> 172.31.64.111:445
02/14/2018-14:03:30.975790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:47979
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:56319
02/14/2018-14:03:48.553165  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55481
02/14/2018-14:03:25.060666  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60300
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64697
02/14/2018-14:03:16.484445  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 113.160.181.58:58523 -> 172.31.64.111:445
02/14/2018-14:03:16.484445  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 113.160.181.58:58523 -> 172.31.64.111:445
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64214
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:53320
02/14/2018-14:03:50.644445  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 117.40.143.50:60598 -> 172.31.64.111:445
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55521
02/14/2018-13:59:42.059432  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:50463
02/14/2018-13:55:56.779155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52067
02/14/2018-14:03:54.831383  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 117.40.143.50:61016 -> 172.31.64.111:445
02/14/2018-14:03:50.882662  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 117.40.143.50:60598 -> 172.31.64.111:445
02/14/2018-14:03:50.882662  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 117.40.143.50:60598 -> 172.31.64.111:445
02/14/2018-13:59:44.715487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59822
02/14/2018-14:04:01.400269  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.135.124.169:26706 -> 172.31.64.111:445
02/14/2018-14:04:28.268558  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57755
02/14/2018-14:04:05.268421  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.135.124.169:26612 -> 172.31.64.111:445
02/14/2018-14:04:01.561233  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.135.124.169:26706 -> 172.31.64.111:445
02/14/2018-14:04:01.561233  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.135.124.169:26706 -> 172.31.64.111:445
02/14/2018-14:04:12.639932  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58076
02/14/2018-14:04:33.688576  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57013
02/14/2018-14:04:42.394698  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49626
02/14/2018-14:04:48.077027  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:45472
02/14/2018-14:04:24.830143  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:7679
02/14/2018-14:05:13.472030  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64586
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65043
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54095
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:49208
02/14/2018-14:05:09.940259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:65470
02/14/2018-14:05:29.877231  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51025
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58197
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64547
02/14/2018-14:06:01.065174  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55779
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:56088
02/14/2018-14:06:01.768812  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55779
02/14/2018-14:05:59.027906  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 58.57.192.50:7537 -> 172.31.64.111:445
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:56212
02/14/2018-14:06:03.326949  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 58.57.192.50:16449 -> 172.31.64.111:445
02/14/2018-14:06:14.328479  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54897
02/14/2018-14:05:59.290258  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 58.57.192.50:7537 -> 172.31.64.111:445
02/14/2018-14:05:59.290258  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 58.57.192.50:7537 -> 172.31.64.111:445
02/14/2018-14:06:31.746491  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56838
02/14/2018-14:01:34.525804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62730
02/14/2018-14:06:23.730327  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:60061
02/14/2018-14:02:31.019549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60131
02/14/2018-14:07:15.161309  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62688
02/14/2018-14:02:31.019549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53570
02/14/2018-14:06:44.551972  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:54789
02/14/2018-14:07:21.294895  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.248.38.193:13774 -> 172.31.64.111:445
02/14/2018-14:06:44.908354  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:54789
02/14/2018-14:06:45.517684  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:54789
02/14/2018-14:02:31.019549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64802
02/14/2018-14:07:21.612468  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.248.38.193:13774 -> 172.31.64.111:445
02/14/2018-14:07:21.612468  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.248.38.193:13774 -> 172.31.64.111:445
02/14/2018-14:07:46.923159  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55947
02/14/2018-14:07:23.360672  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:49706
02/14/2018-14:07:37.464002  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55194
02/14/2018-14:07:38.156924  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55194
02/14/2018-14:07:25.865769  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.248.38.193:14262 -> 172.31.64.111:445
02/14/2018-14:08:21.135959  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64031
02/14/2018-14:08:16.219809  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56866
02/14/2018-14:08:41.584898  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:63916
02/14/2018-14:09:01.438551  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51231
02/14/2018-14:08:30.457612  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63388
02/14/2018-14:03:22.538981  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51610
02/14/2018-14:09:33.136862  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 111.68.102.20:61163 -> 172.31.64.111:445
02/14/2018-14:09:37.357135  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 111.68.102.20:50475 -> 172.31.64.111:445
02/14/2018-14:09:17.401310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51072
02/14/2018-14:09:53.937080  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:28800
02/14/2018-14:09:33.386153  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 111.68.102.20:61163 -> 172.31.64.111:445
02/14/2018-14:09:33.386153  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 111.68.102.20:61163 -> 172.31.64.111:445
02/14/2018-14:03:22.538981  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:53553
02/14/2018-14:10:18.316123  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61335
02/14/2018-14:10:10.934861  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54853
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53041
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55883
02/14/2018-14:11:19.178250  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55285
02/14/2018-14:05:58.227804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:49432
02/14/2018-14:12:20.240880  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49367
02/14/2018-14:12:04.177247  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:50400
02/14/2018-14:05:58.227804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64284
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49637
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62813
02/14/2018-14:12:01.367940  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62044
02/14/2018-14:07:12.619884  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62502
02/14/2018-14:12:29.049465  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:64747
02/14/2018-14:13:49.018859  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:52485
02/14/2018-14:13:22.083322  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60357
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52831
02/14/2018-14:12:43.998311  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.7.242.98:49595 -> 172.31.64.111:445
02/14/2018-14:06:09.709000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60775
02/14/2018-14:12:33.414341  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51429
02/14/2018-14:13:51.231664  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52867
02/14/2018-14:12:39.664736  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 61.7.242.98:65504 -> 172.31.64.111:445
02/14/2018-14:12:39.930928  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.7.242.98:65504 -> 172.31.64.111:445
02/14/2018-14:12:39.930928  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 61.7.242.98:65504 -> 172.31.64.111:445
02/14/2018-14:08:13.322028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:65470
02/14/2018-14:08:13.322028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51025
02/14/2018-14:08:13.322028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:53335
02/14/2018-14:08:13.322028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:47979
02/14/2018-14:14:24.564686  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55279
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64586
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57013
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:50814
02/14/2018-14:14:26.280078  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:60855
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58076
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:7679
02/14/2018-14:08:13.322028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60300
02/14/2018-14:14:30.180835  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:31402
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58812
02/14/2018-14:11:36.822936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:45472
02/14/2018-14:11:36.822936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55481
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:63424
02/14/2018-14:11:36.822936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59538
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50330
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49626
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55779
02/14/2018-14:11:36.822936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58400
02/14/2018-14:14:42.027463  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.1.201.230:52481 -> 172.31.64.111:445
02/14/2018-14:14:42.144964  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.1.201.230:52481 -> 172.31.64.111:445
02/14/2018-14:14:42.144964  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.1.201.230:52481 -> 172.31.64.111:445
02/14/2018-14:14:45.615499  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.1.201.230:52858 -> 172.31.64.111:445
02/14/2018-14:11:16.356993  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57755
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:60061
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56838
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51072
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51231
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:49706
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54897
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55194
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64031
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55947
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56866
02/14/2018-14:14:42.039180  [**] [1:2018959:4] ET POLICY PE EXE or DLL Windows file download HTTP [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 13.107.4.50:80 -> 172.31.64.111:50086
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:54789
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62688
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63388
02/14/2018-14:12:13.858495  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:28800
02/14/2018-14:15:26.376162  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49857
02/14/2018-14:15:41.461317  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60056
02/14/2018-14:16:05.927921  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51620
02/14/2018-14:16:00.119734  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.83.225.95:36541 -> 172.31.64.111:445
02/14/2018-14:16:04.383985  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 183.83.225.95:36604 -> 172.31.64.111:445
02/14/2018-14:16:00.370026  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.83.225.95:36541 -> 172.31.64.111:445
02/14/2018-14:16:27.581114  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60397
02/14/2018-14:16:34.927536  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4589
02/14/2018-14:16:00.370026  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 183.83.225.95:36541 -> 172.31.64.111:445
02/14/2018-14:16:35.643270  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4589
02/14/2018-14:17:30.953613  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50876
02/14/2018-14:17:28.857433  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54711
02/14/2018-14:18:05.341693  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49529
02/14/2018-14:18:30.251207  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65321
02/14/2018-14:13:46.860315  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54853
02/14/2018-14:18:35.329691  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.176.204.133:49160 -> 172.31.64.111:445
02/14/2018-14:18:40.532338  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61265
02/14/2018-14:18:38.770195  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.176.204.133:49490 -> 172.31.64.111:445
02/14/2018-14:13:46.860315  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55285
02/14/2018-14:18:35.418769  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.176.204.133:49160 -> 172.31.64.111:445
02/14/2018-14:18:35.418769  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.176.204.133:49160 -> 172.31.64.111:445
02/14/2018-14:18:51.003782  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:56130
02/14/2018-14:19:20.766251  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58058
02/14/2018-14:13:46.860315  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61335
02/14/2018-14:19:34.246187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59912
02/14/2018-14:19:31.267118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59357
02/14/2018-14:20:04.843406  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.47.184.12:54217 -> 172.31.64.111:445
02/14/2018-14:20:08.667443  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 88.47.184.12:54617 -> 172.31.64.111:445
02/14/2018-14:20:05.063418  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.47.184.12:54217 -> 172.31.64.111:445
02/14/2018-14:20:05.063418  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 88.47.184.12:54217 -> 172.31.64.111:445
02/14/2018-14:20:32.181888  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52609
02/14/2018-14:20:57.218488  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63179
02/14/2018-14:14:48.214831  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51429
02/14/2018-14:14:48.214831  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:50400
02/14/2018-14:21:10.494272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65238
02/14/2018-14:14:48.214867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:64747
02/14/2018-14:14:48.214867  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49367
02/14/2018-14:14:48.214870  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62044
02/14/2018-14:21:46.961275  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61760
02/14/2018-14:21:33.154086  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62822
02/14/2018-14:22:04.482973  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63188
02/14/2018-14:22:05.644645  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49318
02/14/2018-14:22:34.530344  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56785
02/14/2018-14:22:41.069536  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58219
02/14/2018-14:22:45.697235  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64253
02/14/2018-14:23:00.547811  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56041
02/14/2018-14:23:11.480537  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51991
02/14/2018-14:23:36.063139  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50759
02/14/2018-14:23:40.970541  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61845
02/14/2018-14:24:02.298284  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:57892
02/14/2018-14:24:04.889887  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57784
02/14/2018-14:24:11.903601  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50806
02/14/2018-14:24:19.103610  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:52786
02/14/2018-14:24:16.714702  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 46.130.61.241:50733 -> 172.31.64.111:445
02/14/2018-14:24:17.017786  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63959
02/14/2018-14:24:24.303662  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:49761
02/14/2018-14:24:37.893399  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61509
02/14/2018-14:24:50.579284  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63205
02/14/2018-14:24:51.615037  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63205
02/14/2018-14:24:37.955128  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:60499
02/14/2018-14:25:39.258852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55475
02/14/2018-14:26:30.507755  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:54641
02/14/2018-14:26:40.231358  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53994
02/14/2018-14:26:44.705833  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52175
02/14/2018-14:26:44.055041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:51359
02/14/2018-14:27:14.650015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:50835
02/14/2018-14:26:40.317164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65289
02/14/2018-14:27:41.102545  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58730
02/14/2018-14:27:51.638546  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:57650
02/14/2018-14:27:50.713852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62005
02/14/2018-14:26:58.413468  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64982
02/14/2018-14:28:41.963526  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50743
02/14/2018-14:28:30.086378  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61151
02/14/2018-14:28:46.993610  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61906
02/14/2018-14:29:34.721125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61669
02/14/2018-14:29:34.393947  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60980
02/14/2018-14:29:42.662522  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60356
02/14/2018-14:30:18.266072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52355
02/14/2018-14:30:19.793870  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51941
02/14/2018-14:31:13.442332  [**] [1:2403392:58049] ET CINS Active Threat Intelligence Poor Reputation IP group 93 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 94.102.49.190:23183 -> 172.31.64.111:37777
02/14/2018-14:32:10.999706  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59102
02/14/2018-14:31:47.905115  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63353
02/14/2018-14:30:44.235999  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53413
02/14/2018-14:32:52.786258  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58014
02/14/2018-14:33:56.286896  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51873
02/14/2018-14:33:26.716380  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 185.22.153.209:5171 -> 172.31.64.111:5060
02/14/2018-14:33:26.716380  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 185.22.153.209:5171 -> 172.31.64.111:5060
02/14/2018-14:33:51.286365  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52525
02/14/2018-14:34:00.959115  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49888
02/14/2018-14:34:07.515042  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.72.63.209:34427 -> 172.31.64.111:445
02/14/2018-14:34:07.638224  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.72.63.209:34427 -> 172.31.64.111:445
02/14/2018-14:34:07.638224  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.72.63.209:34427 -> 172.31.64.111:445
02/14/2018-14:34:11.132118  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.72.63.209:34506 -> 172.31.64.111:445
02/14/2018-14:34:13.132476  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54869
02/14/2018-14:34:21.288063  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64375
02/14/2018-14:34:38.915410  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64345
02/14/2018-14:35:20.897161  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64806
02/14/2018-14:34:57.803050  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61971
02/14/2018-14:35:50.629878  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57047
02/14/2018-14:36:34.243677  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 159.89.134.235:16762 -> 172.31.64.111:3389
02/14/2018-14:36:44.116257  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5079 -> 172.31.64.111:5060
02/14/2018-14:36:44.116257  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5079 -> 172.31.64.111:5060
02/14/2018-14:35:58.339741  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55260
02/14/2018-14:36:15.398948  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 159.224.229.15:65087 -> 172.31.64.111:445
02/14/2018-14:36:11.520913  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 159.224.229.15:64683 -> 172.31.64.111:445
02/14/2018-14:36:59.515922  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64847
02/14/2018-14:37:23.470712  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52692
02/14/2018-14:36:11.686308  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 159.224.229.15:64683 -> 172.31.64.111:445
02/14/2018-14:36:11.686308  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 159.224.229.15:64683 -> 172.31.64.111:445
02/14/2018-14:37:40.290649  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64203
02/14/2018-14:37:41.282887  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64203
02/14/2018-14:37:03.693209  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:62367
02/14/2018-14:36:28.301425  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:55787
02/14/2018-14:38:07.494806  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60055
02/14/2018-14:38:53.389056  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57727
02/14/2018-14:39:35.632668  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:50149
02/14/2018-14:40:13.973310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:24397
02/14/2018-14:40:11.606276  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:20763
02/14/2018-14:39:30.274272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54987
02/14/2018-14:40:27.366223  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52761
02/14/2018-14:39:18.288535  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57043
02/14/2018-14:41:22.367248  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62137
02/14/2018-14:40:56.831703  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52853
02/14/2018-14:42:43.169357  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:54117
02/14/2018-14:42:46.686150  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60649
02/14/2018-14:41:37.438221  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64720
02/14/2018-14:43:07.905369  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65186
02/14/2018-14:41:59.656836  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:59643
02/14/2018-14:43:35.592035  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:56508
02/14/2018-14:43:41.059508  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 93.80.29.108:58877 -> 172.31.64.111:445
02/14/2018-14:43:15.248557  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52913
02/14/2018-14:43:37.386539  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 93.80.29.108:58498 -> 172.31.64.111:445
02/14/2018-14:43:47.915020  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.243.219.125:64625 -> 172.31.64.111:445
02/14/2018-14:43:37.521048  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 93.80.29.108:58498 -> 172.31.64.111:445
02/14/2018-14:43:37.521048  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 93.80.29.108:58498 -> 172.31.64.111:445
02/14/2018-14:43:48.169084  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.243.219.125:64625 -> 172.31.64.111:445
02/14/2018-14:43:48.169084  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.243.219.125:64625 -> 172.31.64.111:445
02/14/2018-14:43:55.394790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56137
02/14/2018-14:45:04.801269  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60058
02/14/2018-14:45:03.517801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51792
02/14/2018-14:43:52.331317  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.243.219.125:65084 -> 172.31.64.111:445
02/14/2018-14:45:20.799507  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 149.202.199.92:5204 -> 172.31.64.111:5060
02/14/2018-14:45:20.799507  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 149.202.199.92:5204 -> 172.31.64.111:5060
02/14/2018-14:46:04.190751  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57148
02/14/2018-14:46:11.544519  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63943
02/14/2018-14:44:30.112304  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53007
02/14/2018-14:46:23.940284  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5084 -> 172.31.64.111:5060
02/14/2018-14:46:23.940284  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5084 -> 172.31.64.111:5060
02/14/2018-14:47:00.782547  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.22.171.56:56875 -> 172.31.64.111:445
02/14/2018-14:47:14.292757  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:49333
02/14/2018-14:46:53.870915  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50833
02/14/2018-14:47:00.983656  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.22.171.56:56875 -> 172.31.64.111:445
02/14/2018-14:47:00.983656  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.22.171.56:56875 -> 172.31.64.111:445
02/14/2018-14:47:17.045073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60358
02/14/2018-14:47:17.752654  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60358
02/14/2018-14:47:20.100470  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60181
02/14/2018-14:47:19.065176  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60358
02/14/2018-14:48:03.256170  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53157
02/14/2018-14:47:04.770455  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.22.171.56:55917 -> 172.31.64.111:445
02/14/2018-14:48:28.421671  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56117
02/14/2018-14:48:43.445407  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57970
02/14/2018-14:48:54.472567  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58049
02/14/2018-14:49:36.682879  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52358
02/14/2018-14:50:14.808240  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:63258
02/14/2018-14:49:50.935653  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:53358
02/14/2018-14:50:32.633367  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65107
02/14/2018-14:50:32.939503  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 2.92.200.247:56232 -> 172.31.64.111:445
02/14/2018-14:50:45.383151  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64906
02/14/2018-14:50:33.093726  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 2.92.200.247:56232 -> 172.31.64.111:445
02/14/2018-14:50:48.094679  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 50.201.141.102:20756 -> 172.31.64.111:445
02/14/2018-14:50:33.093726  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 2.92.200.247:56232 -> 172.31.64.111:445
02/14/2018-14:50:36.719529  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 2.92.200.247:57003 -> 172.31.64.111:445
02/14/2018-14:50:51.166855  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 50.201.141.102:36475 -> 172.31.64.111:445
02/14/2018-14:50:48.108701  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 50.201.141.102:20756 -> 172.31.64.111:445
02/14/2018-14:50:48.108701  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 50.201.141.102:20756 -> 172.31.64.111:445
02/14/2018-14:51:19.229715  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.199.161.11:64323 -> 172.31.64.111:445
02/14/2018-14:51:14.772034  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.199.161.11:54985 -> 172.31.64.111:445
02/14/2018-14:51:23.597493  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 35.165.11.195:60534
02/14/2018-14:51:15.059473  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.199.161.11:54985 -> 172.31.64.111:445
02/14/2018-14:51:15.059473  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.199.161.11:54985 -> 172.31.64.111:445
02/14/2018-14:51:37.538083  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53299
02/14/2018-14:51:53.848053  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60926
02/14/2018-14:11:37.916544  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:63916
02/14/2018-14:52:08.300049  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:51733
02/14/2018-14:52:23.197430  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55873
02/14/2018-14:53:04.684097  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:60672
02/14/2018-14:52:50.526103  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:65295
02/14/2018-14:53:02.252459  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56819
02/14/2018-14:53:37.131624  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:34132
02/14/2018-14:53:50.574506  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:50501
02/14/2018-14:53:42.760708  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:42636
02/14/2018-14:54:20.096978  [**] [1:2403330:58049] ET CINS Active Threat Intelligence Poor Reputation IP group 31 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 46.174.191.29:28282 -> 172.31.64.111:8080
02/14/2018-14:54:11.663482  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53520
02/14/2018-14:55:05.079960  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:48470
02/14/2018-14:55:13.053602  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53438
02/14/2018-14:55:19.327951  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65253
02/14/2018-14:54:12.652997  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63007
02/14/2018-14:56:27.588530  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61059
02/14/2018-14:56:48.799001  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:52620
02/14/2018-14:57:34.562116  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56203
02/14/2018-14:57:51.718716  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:65134
02/14/2018-14:57:51.097974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60911
02/14/2018-14:57:58.874731  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:58246
02/14/2018-14:56:01.818394  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53774
02/14/2018-14:57:59.657952  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53815
02/14/2018-14:58:04.844118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59270
02/14/2018-14:48:32.740133  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:65467
02/14/2018-14:54:52.340208  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:27490
02/14/2018-14:58:11.441821  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 92.45.52.78:55426 -> 172.31.64.111:445
02/14/2018-14:58:21.454227  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 59.90.229.95:50400 -> 172.31.64.111:445
02/14/2018-14:58:16.101981  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53030
02/14/2018-14:58:21.768386  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 59.90.229.95:50400 -> 172.31.64.111:445
02/14/2018-14:58:29.029976  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 59.90.229.95:50869 -> 172.31.64.111:445
02/14/2018-14:58:21.768386  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 59.90.229.95:50400 -> 172.31.64.111:445
02/14/2018-14:58:07.651700  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 92.45.52.78:55043 -> 172.31.64.111:445
02/14/2018-14:58:36.824026  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61111
02/14/2018-14:58:59.395685  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:51914
02/14/2018-14:58:46.363277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53572
02/14/2018-14:58:07.807285  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 92.45.52.78:55043 -> 172.31.64.111:445
02/14/2018-14:58:07.807285  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 92.45.52.78:55043 -> 172.31.64.111:445
02/14/2018-14:58:20.653841  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52618
02/14/2018-14:59:17.251868  [**] [1:2402000:5577] ET DROP Dshield Block Listed Source group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 89.248.168.14:65534 -> 172.31.64.111:8545
02/14/2018-14:58:54.639027  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:2134
02/14/2018-14:58:59.864241  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:55173
02/14/2018-14:58:55.297355  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:2134
02/14/2018-14:59:32.976280  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65197
02/14/2018-14:59:40.527185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51672
02/14/2018-14:59:33.624536  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65197
02/14/2018-14:58:28.020699  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57647
02/14/2018-14:59:40.685191  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 197.160.33.238:54520 -> 172.31.64.111:445
02/14/2018-14:59:49.013433  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63164
02/14/2018-14:59:41.303864  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 197.160.33.238:54520 -> 172.31.64.111:445
02/14/2018-14:59:36.657938  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 197.160.33.238:54065 -> 172.31.64.111:445
02/14/2018-14:59:10.901185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62894
02/14/2018-14:59:11.421971  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62894
02/14/2018-14:59:36.837242  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 197.160.33.238:54065 -> 172.31.64.111:445
02/14/2018-14:59:36.837242  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 197.160.33.238:54065 -> 172.31.64.111:445
02/14/2018-15:00:10.218153  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52852
02/14/2018-15:00:19.438968  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:46435
02/14/2018-15:00:28.811295  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57989
02/14/2018-15:00:31.826142  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57989
02/14/2018-15:00:20.729288  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62405
02/14/2018-15:00:21.248351  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62405
02/14/2018-15:00:22.185827  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62405
02/14/2018-15:00:06.950301  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60567
02/14/2018-15:00:34.241047  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:52946
02/14/2018-15:00:40.078030  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55536
02/14/2018-15:00:54.234041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57345
02/14/2018-15:01:29.847840  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58804
02/14/2018-15:02:02.998126  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64791
02/14/2018-15:02:14.343074  [**] [1:2400007:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 8 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 123.249.24.175:6000 -> 172.31.64.111:3306
02/14/2018-15:02:14.343074  [**] [1:2010937:3] ET SCAN Suspicious inbound to mySQL port 3306 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 123.249.24.175:6000 -> 172.31.64.111:3306
02/14/2018-15:02:01.267123  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50932
02/14/2018-15:02:20.176333  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:54867
02/14/2018-15:02:07.283770  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.154.118.59:2525 -> 172.31.64.111:445
02/14/2018-15:02:11.565711  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.154.118.59:2526 -> 172.31.64.111:445
02/14/2018-15:03:08.641263  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59052
02/14/2018-15:02:07.543183  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.154.118.59:2525 -> 172.31.64.111:445
02/14/2018-15:02:07.543183  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.154.118.59:2525 -> 172.31.64.111:445
02/14/2018-15:02:22.491738  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 116.206.176.70:59441 -> 172.31.64.111:445
02/14/2018-15:03:19.414890  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59555
02/14/2018-15:03:19.993788  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59555
02/14/2018-15:03:19.273678  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58872
02/14/2018-15:02:26.614015  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 116.206.176.70:59881 -> 172.31.64.111:445
02/14/2018-15:02:22.714279  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 116.206.176.70:59441 -> 172.31.64.111:445
02/14/2018-15:02:22.714279  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 116.206.176.70:59441 -> 172.31.64.111:445
02/14/2018-15:03:25.133071  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64441
02/14/2018-15:03:19.503422  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49548
02/14/2018-15:05:08.756918  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56687
02/14/2018-15:05:12.545316  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:54642
02/14/2018-15:04:02.347793  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:05:21.525999  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56421
02/14/2018-15:04:15.318802  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50131
02/14/2018-15:04:02.883293  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:05:09.741003  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56687
02/14/2018-15:04:03.836399  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:04:05.742604  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:05:28.977561  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:63963
02/14/2018-15:04:09.539397  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:05:53.469020  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:54989
02/14/2018-15:06:26.924506  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63638
02/14/2018-15:06:57.727353  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63813
02/14/2018-15:05:28.117447  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64153
02/14/2018-15:07:30.104861  [**] [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 221.194.44.101:6000 -> 172.31.64.111:1433
02/14/2018-15:07:31.208334  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.39.216.134:35037
02/14/2018-15:07:31.312339  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 5.39.216.134:35037
02/14/2018-15:08:41.424095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53486
02/14/2018-15:08:47.084660  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54562
02/14/2018-15:07:34.004208  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58464
02/14/2018-15:08:58.318806  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:58727
02/14/2018-15:09:01.878077  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:55121
02/14/2018-15:09:23.289228  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.248.86.234:21658 -> 172.31.64.111:445
02/14/2018-15:09:48.057217  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64556
02/14/2018-15:09:19.837833  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.248.86.234:13583 -> 172.31.64.111:445
02/14/2018-15:09:27.544309  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55102
02/14/2018-15:09:19.936231  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.248.86.234:13583 -> 172.31.64.111:445
02/14/2018-15:09:19.936231  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.248.86.234:13583 -> 172.31.64.111:445
02/14/2018-15:10:36.080069  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61679
02/14/2018-15:10:55.237639  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59431
02/14/2018-15:11:23.198014  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.29.189.238:11981 -> 172.31.64.111:445
02/14/2018-15:11:23.349674  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.29.189.238:11981 -> 172.31.64.111:445
02/14/2018-15:11:23.349674  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.29.189.238:11981 -> 172.31.64.111:445
02/14/2018-15:11:26.963191  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.29.189.238:12388 -> 172.31.64.111:445
02/14/2018-15:12:02.232120  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53933
02/14/2018-15:12:26.046379  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52426
02/14/2018-15:11:54.787619  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51510
02/14/2018-15:13:09.243175  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64694
02/14/2018-15:13:01.191787  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55212
02/14/2018-15:14:08.585907  [**] [1:2400019:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 20 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 191.101.167.235:40067 -> 172.31.64.111:8545
02/14/2018-15:13:26.291600  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62519
02/14/2018-15:14:14.787824  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59540
02/14/2018-15:14:16.818696  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59001
02/14/2018-15:15:23.675672  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53165
02/14/2018-15:16:03.756920  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50278
02/14/2018-15:16:30.632988  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63962
02/14/2018-15:16:33.473399  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55304
02/14/2018-15:16:57.592975  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:49765
02/14/2018-15:17:01.267588  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.151.179.45:4881 -> 172.31.64.111:445
02/14/2018-15:17:05.077681  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.151.179.45:2299 -> 172.31.64.111:445
02/14/2018-15:17:25.932290  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56815
02/14/2018-15:17:01.442064  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.151.179.45:4881 -> 172.31.64.111:445
02/14/2018-15:17:01.442064  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.151.179.45:4881 -> 172.31.64.111:445
02/14/2018-15:17:47.519231  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:59668
02/14/2018-15:17:53.043592  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57389
02/14/2018-15:18:13.580028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:62563
02/14/2018-15:18:43.723202  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52327
02/14/2018-15:18:58.336264  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:50478
02/14/2018-15:19:05.968812  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52137
02/14/2018-15:19:42.550030  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64492
02/14/2018-15:20:06.792684  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55392
02/14/2018-15:19:53.305705  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64373
02/14/2018-15:20:24.021792  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.236.82.114:52070 -> 172.31.64.111:445
02/14/2018-15:20:24.236941  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.236.82.114:52070 -> 172.31.64.111:445
02/14/2018-15:20:24.236941  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.236.82.114:52070 -> 172.31.64.111:445
02/14/2018-15:20:28.090368  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.236.82.114:52491 -> 172.31.64.111:445
02/14/2018-15:21:00.616060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59055
02/14/2018-15:20:59.122443  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:63488
02/14/2018-15:21:31.602873  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55225
02/14/2018-15:21:52.001956  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:64606
02/14/2018-15:22:03.427171  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52208
02/14/2018-15:22:58.008260  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 31.132.225.66:49250 -> 172.31.64.111:445
02/14/2018-15:22:58.220710  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 31.132.225.66:49250 -> 172.31.64.111:445
02/14/2018-15:22:58.220710  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 31.132.225.66:49250 -> 172.31.64.111:445
02/14/2018-15:23:02.070482  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 31.132.225.66:47424 -> 172.31.64.111:445
02/14/2018-15:23:21.460348  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62325
02/14/2018-15:23:39.250135  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55472
02/14/2018-15:24:01.060368  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51010
02/14/2018-15:24:46.808143  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:56641
02/14/2018-14:19:39.310792  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51806
02/14/2018-14:21:03.722047  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:64001
02/14/2018-15:25:11.100567  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53054
02/14/2018-15:23:02.583003  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59856
02/14/2018-15:24:59.470099  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58447
02/14/2018-14:24:12.757299  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 46.130.61.241:50349 -> 172.31.64.111:445
02/14/2018-15:25:43.944402  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 201.210.225.161:49980 -> 172.31.64.111:445
02/14/2018-15:25:47.561564  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 201.210.225.161:50353 -> 172.31.64.111:445
02/14/2018-15:25:44.069338  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 201.210.225.161:49980 -> 172.31.64.111:445
02/14/2018-15:25:44.069338  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 201.210.225.161:49980 -> 172.31.64.111:445
02/14/2018-15:25:54.346260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:59418
02/14/2018-14:24:12.939313  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 46.130.61.241:50349 -> 172.31.64.111:445
02/14/2018-14:24:12.939313  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 46.130.61.241:50349 -> 172.31.64.111:445
02/14/2018-15:25:56.634628  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.21.221.6:58428 -> 172.31.64.111:445
02/14/2018-15:25:57.925733  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49488
02/14/2018-15:25:52.984368  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.21.221.6:57641 -> 172.31.64.111:445
02/14/2018-14:24:13.133307  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55279
02/14/2018-15:25:53.125573  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.21.221.6:57641 -> 172.31.64.111:445
02/14/2018-15:25:53.125573  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.21.221.6:57641 -> 172.31.64.111:445
02/14/2018-14:29:47.073598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60397
02/14/2018-14:24:13.133352  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50876
02/14/2018-15:26:27.223475  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.149.241.210:52294 -> 172.31.64.111:445
02/14/2018-14:29:47.073598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49529
02/14/2018-14:29:47.073598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51620
02/14/2018-15:27:04.429812  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59457
02/14/2018-14:30:19.580549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:31402
02/14/2018-14:30:19.602188  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59357
02/14/2018-15:26:27.301571  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.149.241.210:52294 -> 172.31.64.111:445
02/14/2018-15:26:27.301571  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.149.241.210:52294 -> 172.31.64.111:445
02/14/2018-14:30:19.580549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52867
02/14/2018-14:30:19.628185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52609
02/14/2018-14:30:19.628093  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:52485
02/14/2018-15:26:59.972976  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60151
02/14/2018-14:30:19.628150  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60357
02/14/2018-15:27:10.945889  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 83.149.47.190:55432 -> 172.31.64.111:445
02/14/2018-14:30:19.628150  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60056
02/14/2018-15:27:06.915727  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 83.149.47.190:59278 -> 172.31.64.111:445
02/14/2018-14:30:19.580549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65321
02/14/2018-15:26:30.587267  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.149.241.210:52640 -> 172.31.64.111:445
02/14/2018-14:30:19.629705  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65238
02/14/2018-15:27:07.125762  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 83.149.47.190:59278 -> 172.31.64.111:445
02/14/2018-15:27:07.125762  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 83.149.47.190:59278 -> 172.31.64.111:445
02/14/2018-14:30:19.652106  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:56130
02/14/2018-14:30:19.652106  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49857
02/14/2018-14:30:19.580549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4589
02/14/2018-15:27:12.188429  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55541
02/14/2018-14:30:19.628185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63188
02/14/2018-14:30:19.653558  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61760
02/14/2018-14:30:19.653062  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58058
02/14/2018-14:33:00.914194  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59912
02/14/2018-14:33:00.914158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54711
02/14/2018-14:30:19.653062  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62822
02/14/2018-14:33:01.094450  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61265
02/14/2018-14:33:01.449195  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 189.42.6.166:59375 -> 172.31.64.111:445
02/14/2018-14:33:01.626402  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 189.42.6.166:59375 -> 172.31.64.111:445
02/14/2018-14:33:01.626402  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 189.42.6.166:59375 -> 172.31.64.111:445
02/14/2018-14:30:19.653062  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63179
02/14/2018-14:33:05.337207  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 189.42.6.166:59770 -> 172.31.64.111:445
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:57892
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63205
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64345
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60356
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50743
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65289
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61669
02/14/2018-14:38:10.520354  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:50835
02/14/2018-14:38:10.496582  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51873
02/14/2018-14:38:10.687046  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58014
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55475
02/14/2018-14:38:10.521685  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53413
02/14/2018-14:38:10.520354  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51941
02/14/2018-14:40:54.771045  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64375
02/14/2018-14:38:18.441569  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63959
02/14/2018-14:38:10.520354  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57784
02/14/2018-14:40:54.770956  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52355
02/14/2018-14:41:54.779952  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61971
02/14/2018-14:41:55.100794  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:51359
02/14/2018-14:40:54.771045  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56041
02/14/2018-14:39:18.631435  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53994
02/14/2018-14:40:54.771045  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:61906
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:56877
02/14/2018-14:41:54.780046  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58219
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:54641
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61151
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:60499
02/14/2018-14:41:56.031093  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61509
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64806
02/14/2018-14:41:56.446888  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56785
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:49761
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61845
02/14/2018-14:41:55.103405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64253
02/14/2018-14:44:48.657166  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50759
02/14/2018-14:44:48.657166  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59102
02/14/2018-14:44:48.657166  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:57650
02/14/2018-14:44:48.657166  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60980
02/14/2018-14:44:48.681801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52525
02/14/2018-14:44:48.681801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62005
02/14/2018-14:44:48.681801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49888
02/14/2018-14:44:48.683077  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57047
02/14/2018-14:44:48.681801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52175
02/14/2018-14:44:48.706353  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55260
02/14/2018-14:44:48.683077  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:64982
02/14/2018-14:46:20.181870  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51991
02/14/2018-14:49:23.190152  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:52786
02/14/2018-14:49:23.190152  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54869
02/14/2018-14:58:41.556962  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51036
02/14/2018-14:30:19.629705  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49318
02/14/2018-15:03:36.504404  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54479
02/14/2018-15:16:23.568791  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57148
02/14/2018-15:16:23.630072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:52946
02/14/2018-14:38:10.495118  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58730
02/14/2018-15:17:37.009978  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58056
02/14/2018-15:16:23.568791  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62137
02/14/2018-15:17:36.764717  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63813
02/14/2018-15:17:37.009978  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56117
02/14/2018-15:17:36.764717  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52761
02/14/2018-15:17:36.764717  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:27490
02/14/2018-15:17:37.991207  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56687
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52852
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52618
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61679
02/14/2018-15:17:23.582029  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52692
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:60672
02/14/2018-15:17:37.748010  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56203
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50833
02/14/2018-15:17:37.007719  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54562
02/14/2018-15:16:23.630072  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55102
02/14/2018-15:17:37.255110  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:55787
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50131
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:62367
02/14/2018-15:17:36.764717  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:52853
02/14/2018-15:19:11.392820  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56421
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57043
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62519
02/14/2018-15:17:37.255110  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62894
02/14/2018-14:40:54.770956  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50806
02/14/2018-15:21:17.686095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60181
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50932
02/14/2018-14:42:01.253553  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63353
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53933
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64906
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:24397
02/14/2018-15:21:17.544298  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:48470
02/14/2018-15:17:37.007716  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65197
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53299
02/14/2018-15:21:17.747187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52358
02/14/2018-15:21:17.747189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:61111
02/14/2018-15:17:37.009978  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:42636
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52913
02/14/2018-15:21:17.747189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57989
02/14/2018-15:21:17.692025  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:65295
02/14/2018-15:17:37.255110  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:54642
02/14/2018-15:21:17.608281  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59555
02/14/2018-15:17:37.503537  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54987
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:65186
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58872
02/14/2018-15:21:17.686095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:65134
02/14/2018-15:17:39.246474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:50501
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58049
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64791
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:55173
02/14/2018-15:21:17.610026  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:52620
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51792
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:49333
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53815
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51510
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60649
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59052
02/14/2018-15:21:17.747189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65107
02/14/2018-15:21:17.747187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63007
02/14/2018-15:21:17.686095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:51914
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56137
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60567
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60926
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:59643
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:50149
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64694
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58804
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53007
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:20763
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53157
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:54867
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53486
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64556
02/14/2018-15:21:17.747187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55536
02/14/2018-15:21:17.747187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 35.165.11.195:60534
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63638
02/14/2018-15:19:11.391781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52426
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:51733
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53520
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60058
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53572
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:62510
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49548
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57727
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55873
02/14/2018-15:19:11.392058  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:63963
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:55121
02/14/2018-15:19:11.392119  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60055
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51672
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57970
02/14/2018-15:19:11.392690  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60911
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64720
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59431
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:64441
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:56508
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:46435
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58464
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64847
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65253
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56819
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62405
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64153
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57647
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:2134
02/14/2018-15:21:17.544298  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:63258
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:65467
02/14/2018-15:28:10.705109  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:50420
02/14/2018-15:28:11.462190  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53173
02/14/2018-15:21:17.608281  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59270
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:53358
02/14/2018-15:21:17.747215  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64203
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:34132
02/14/2018-15:17:36.764717  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:54989
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60358
02/14/2018-15:28:29.419875  [**] [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 221.229.204.124:6000 -> 172.31.64.111:1433
02/14/2018-15:19:11.392690  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:53438
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53774
02/14/2018-15:19:11.392974  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59001
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:54117
02/14/2018-15:28:44.981574  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:65532
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63943
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53030
02/14/2018-15:21:17.687748  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57345
02/14/2018-15:21:17.747187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:58727
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55212
02/14/2018-15:28:53.062456  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59147
02/14/2018-15:29:07.899817  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51206
02/14/2018-15:28:48.918857  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50878
02/14/2018-15:30:04.549487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58965
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59540
02/14/2018-15:30:24.587421  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56453
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:49765
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52137
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:59668
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:50478
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:62563
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63962
02/14/2018-15:30:54.192662  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:61144
02/14/2018-15:19:11.392734  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61059
02/14/2018-15:29:19.068240  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63571
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56815
02/14/2018-15:31:12.253678  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63693
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53165
02/14/2018-15:30:59.307967  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57281
02/14/2018-15:30:37.253314  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57974
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57389
02/14/2018-15:31:30.855308  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49559
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52327
02/14/2018-15:31:48.185868  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52289
02/14/2018-15:31:19.880745  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:53625
02/14/2018-15:31:49.059593  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52289
02/14/2018-15:21:17.686095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:58246
02/14/2018-15:31:50.715864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52289
02/14/2018-15:31:43.222872  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 79.174.248.227:51607 -> 172.31.64.111:445
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55304
02/14/2018-15:31:43.342271  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 79.174.248.227:51607 -> 172.31.64.111:445
02/14/2018-15:31:43.342271  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 79.174.248.227:51607 -> 172.31.64.111:445
02/14/2018-15:32:18.101682  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.111:44473 -> 172.31.64.111:5454
02/14/2018-15:31:04.289580  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:64233
02/14/2018-15:32:26.547168  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65070
02/14/2018-15:31:05.201405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:64233
02/14/2018-15:33:06.697754  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58106
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50278
02/14/2018-15:33:53.830668  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57468
02/14/2018-15:33:54.556427  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57468
02/14/2018-15:34:15.772255  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55794
02/14/2018-15:34:15.497630  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56410
02/14/2018-15:34:17.517011  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55658
02/14/2018-15:34:11.723115  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64492
02/14/2018-15:21:17.778934  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63164
02/14/2018-15:34:37.828668  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57199
02/14/2018-15:34:38.367828  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57199
02/14/2018-15:34:36.333849  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52763
02/14/2018-15:34:37.055382  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52763
02/14/2018-15:34:43.859110  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.95.99.203:64595 -> 172.31.64.111:445
02/14/2018-15:30:45.194375  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55603
02/14/2018-15:30:47.932676  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:36641
02/14/2018-15:34:44.016250  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.95.99.203:64595 -> 172.31.64.111:445
02/14/2018-15:34:44.016250  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.95.99.203:64595 -> 172.31.64.111:445
02/14/2018-14:30:19.580549  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:60855
02/14/2018-14:30:19.628185  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:64001
02/14/2018-14:30:19.629705  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:51806
02/14/2018-15:17:37.009978  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51036
02/14/2018-15:21:17.544298  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54479
02/14/2018-15:21:17.610026  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:56877
02/14/2018-15:21:18.110473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58056
02/14/2018-15:31:47.925794  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 79.174.248.227:52616 -> 172.31.64.111:445
02/14/2018-15:32:36.795684  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58876
02/14/2018-15:32:50.636929  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:53640
02/14/2018-15:33:42.492735  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51619
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55225
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49488
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59457
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55541
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51010
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55472
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:59418
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64492
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62325
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53054
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59856
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:56641
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59055
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58447
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52208
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:64606
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:63488
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60151
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55392
02/14/2018-15:29:47.092417  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64373
02/14/2018-15:34:18.311258  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53173
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50878
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59147
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:65532
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51206
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:50420
02/14/2018-15:34:47.607250  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.95.99.203:65014 -> 172.31.64.111:445
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55603
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56453
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58965
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57281
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:36641
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:61144
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:64233
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63571
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49559
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52289
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63693
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:53625
02/14/2018-15:34:26.854842  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57974
02/14/2018-15:34:48.724017  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60848
02/14/2018-15:34:30.385801  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65070
02/14/2018-15:34:59.965808  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59457
02/14/2018-15:34:45.239370  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58876
02/14/2018-15:35:55.066536  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53706
02/14/2018-15:36:04.398171  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62884
02/14/2018-15:36:11.329833  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57941
02/14/2018-15:36:13.702255  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63616
02/14/2018-15:36:12.117556  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63806
02/14/2018-15:36:23.074442  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60508
02/14/2018-15:36:23.630744  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60508
02/14/2018-15:36:55.507874  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61423
02/14/2018-15:37:02.868733  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63309
02/14/2018-15:37:09.712944  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:51238
02/14/2018-15:37:40.335894  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5079 -> 172.31.64.111:5060
02/14/2018-15:37:40.335894  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5079 -> 172.31.64.111:5060
02/14/2018-15:37:53.088731  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53604
02/14/2018-15:37:48.465898  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55708
02/14/2018-15:38:09.549619  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56156
02/14/2018-15:38:05.068678  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 1.55.177.219:33266 -> 172.31.64.111:445
02/14/2018-15:39:08.579983  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63764
02/14/2018-15:39:16.516351  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49429
02/14/2018-15:39:19.780906  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55805
02/14/2018-15:36:05.895742  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58106
02/14/2018-15:36:05.895742  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:57468
02/14/2018-15:39:41.878928  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60688
02/14/2018-15:39:53.896068  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53827
02/14/2018-15:40:23.858299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59442
02/14/2018-15:40:36.076873  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:54401
02/14/2018-15:40:59.888364  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:3050
02/14/2018-15:41:08.557649  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58309
02/14/2018-15:41:09.092236  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58309
02/14/2018-15:41:30.526774  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51409
02/14/2018-15:41:36.109749  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:52789 -> 172.31.64.111:3389
02/14/2018-15:41:39.079126  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:52789 -> 172.31.64.111:3389
02/14/2018-15:41:45.120033  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:52789 -> 172.31.64.111:3389
02/14/2018-15:41:47.178295  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:65506
02/14/2018-15:41:31.756362  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52397
02/14/2018-15:41:19.067787  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55757
02/14/2018-15:36:05.895742  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51619
02/14/2018-15:38:00.772692  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 1.55.177.219:13505 -> 172.31.64.111:445
02/14/2018-15:36:05.895742  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:53640
02/14/2018-15:38:01.029546  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 1.55.177.219:13505 -> 172.31.64.111:445
02/14/2018-15:38:01.029546  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 1.55.177.219:13505 -> 172.31.64.111:445
02/14/2018-15:42:35.331013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:51316
02/14/2018-15:42:38.717563  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62046
02/14/2018-15:43:17.943474  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54564
02/14/2018-15:43:29.693747  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:53646
02/14/2018-15:43:20.249846  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58497
02/14/2018-15:43:41.783011  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:58200
02/14/2018-15:43:43.241204  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54563
02/14/2018-15:44:00.221287  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:59696
02/14/2018-15:44:47.717732  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62676
02/14/2018-15:42:28.824055  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55066
02/14/2018-15:44:42.291139  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:26803
02/14/2018-15:44:38.907338  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:21610
02/14/2018-15:44:50.694662  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55805
02/14/2018-15:37:38.193336  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52763
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56410
02/14/2018-15:43:52.004055  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:10452
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57199
02/14/2018-15:45:53.644908  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54979
02/14/2018-15:45:08.898115  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49196
02/14/2018-15:46:57.485487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56291
02/14/2018-15:46:58.589181  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63818
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55794
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55658
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59457
02/14/2018-15:40:08.306272  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60848
02/14/2018-15:48:02.880581  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56228
02/14/2018-15:39:29.729079  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64492
02/14/2018-15:42:27.858227  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53420
02/14/2018-15:44:41.780119  [**] [1:2403363:58049] ET CINS Active Threat Intelligence Poor Reputation IP group 64 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 66.240.219.146:31231 -> 172.31.64.111:4064
02/14/2018-15:44:12.067132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53604
02/14/2018-15:44:12.067132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60688
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55805
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:61423
02/14/2018-15:44:12.067132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:60508
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:54401
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:51238
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63309
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:3050
02/14/2018-15:44:12.067132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63806
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63764
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:63616
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56156
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49429
02/14/2018-15:44:12.067132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:57941
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55708
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53706
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51409
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53827
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59442
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:65506
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58309
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55757
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62884
02/14/2018-15:44:12.067158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52397
02/14/2018-15:44:49.906451  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:55066
02/14/2018-15:44:49.906451  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:51316
02/14/2018-15:44:49.906451  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62046
02/14/2018-15:44:49.906451  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53420
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:59696
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54563
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62676
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:53646
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:26803
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:10452
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49196
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:58200
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58497
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:21610
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55805
02/14/2018-15:47:29.179164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54564
02/14/2018-15:48:13.550132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54979
02/14/2018-15:50:13.083106  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57719
02/14/2018-15:50:35.058187  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54092
02/14/2018-15:51:15.659085  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65477
02/14/2018-15:52:15.869972  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56260
02/14/2018-15:54:11.796399  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51879
02/14/2018-15:59:07.191070  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49943
02/14/2018-15:59:36.325341  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49349
02/14/2018-15:57:48.571041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49651
02/14/2018-15:59:36.795078  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56737
02/14/2018-15:49:07.825016  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65018
02/14/2018-15:55:14.835908  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59223
02/14/2018-15:51:50.966971  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55898
02/14/2018-15:58:48.654095  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:64405
02/14/2018-15:48:21.065161  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55852
02/14/2018-15:48:46.365007  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63373
02/14/2018-16:00:59.071651  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59954
02/14/2018-15:58:49.640337  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55955
02/14/2018-16:01:55.629804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65324
02/14/2018-16:04:32.296924  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:62234
02/14/2018-16:08:54.235578  [**] [1:2400019:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 20 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 191.101.167.250:57807 -> 172.31.64.111:7588
02/14/2018-16:09:22.467709  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:56422
02/14/2018-15:55:17.497423  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 179.126.7.109:60691 -> 172.31.64.111:445
02/14/2018-16:10:19.616391  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64676
02/14/2018-15:55:17.651958  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 179.126.7.109:60691 -> 172.31.64.111:445
02/14/2018-15:55:17.651958  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 179.126.7.109:60691 -> 172.31.64.111:445
02/14/2018-16:10:11.983913  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54261
02/14/2018-16:10:12.532243  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54261
02/14/2018-16:00:39.996198  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.193:65530 -> 172.31.64.111:5019
02/14/2018-16:07:31.429212  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62983
02/14/2018-16:05:01.916372  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61549
02/14/2018-16:08:26.899115  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51505
02/14/2018-15:55:20.761290  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55930
02/14/2018-16:01:32.463766  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:58958
02/14/2018-16:04:45.028765  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64829
02/14/2018-16:08:37.231680  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59270
02/14/2018-16:06:49.263871  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52224
02/14/2018-16:09:09.606776  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.199.178.153:51411 -> 172.31.64.111:445
02/14/2018-15:59:59.134444  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51544
02/14/2018-15:59:59.844643  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51544
02/14/2018-16:03:13.970786  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54499
02/14/2018-16:06:35.934751  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58084
02/14/2018-15:56:32.150605  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:52057
02/14/2018-15:49:11.669381  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 181.211.10.28:40377 -> 172.31.64.111:445
02/14/2018-15:49:11.774322  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 181.211.10.28:40377 -> 172.31.64.111:445
02/14/2018-15:49:11.774322  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 181.211.10.28:40377 -> 172.31.64.111:445
02/14/2018-15:54:47.969343  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 62.4.158.86:16949 -> 172.31.64.111:445
02/14/2018-16:05:48.565295  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57145
02/14/2018-15:59:52.296577  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:62622
02/14/2018-15:55:21.270544  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 179.126.7.109:61468 -> 172.31.64.111:445
02/14/2018-16:08:11.650596  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58760
02/14/2018-16:01:24.801738  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63806
02/14/2018-16:10:18.081245  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61395
02/14/2018-15:54:05.888015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:59421
02/14/2018-15:56:42.129405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:58105
02/14/2018-16:05:40.573922  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53314
02/14/2018-15:57:12.760316  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55366
02/14/2018-16:06:00.171107  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:60779 -> 172.31.64.111:3389
02/14/2018-16:06:03.339918  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:60779
02/14/2018-15:52:46.293633  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:56241
02/14/2018-15:54:15.798352  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53056
02/14/2018-16:09:05.116666  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.199.178.153:50558 -> 172.31.64.111:445
02/14/2018-16:06:28.241520  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:49599
02/14/2018-15:54:44.427980  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 62.4.158.86:13171 -> 172.31.64.111:445
02/14/2018-16:09:05.419737  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.199.178.153:50558 -> 172.31.64.111:445
02/14/2018-16:09:05.419737  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.199.178.153:50558 -> 172.31.64.111:445
02/14/2018-15:54:44.545473  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 62.4.158.86:13171 -> 172.31.64.111:445
02/14/2018-15:54:44.545473  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 62.4.158.86:13171 -> 172.31.64.111:445
02/14/2018-16:09:08.966979  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57129
02/14/2018-15:55:54.135329  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:25968
02/14/2018-15:52:23.699784  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61170
02/14/2018-16:00:03.168297  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55041
02/14/2018-16:02:52.175333  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54223
02/14/2018-16:01:45.831423  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51520
02/14/2018-16:09:22.549469  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56526
02/14/2018-15:59:08.728529  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58701
02/14/2018-16:02:19.341033  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57140
02/14/2018-16:09:18.160214  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57147
02/14/2018-15:56:13.489887  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65228
02/14/2018-15:49:15.191330  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 181.211.10.28:40378 -> 172.31.64.111:445
02/14/2018-15:51:32.068922  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:48606
02/14/2018-15:51:35.076325  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:48606
02/14/2018-15:53:15.811931  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62953
02/14/2018-15:49:08.387140  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62923
02/14/2018-16:07:03.117480  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62022
02/14/2018-15:59:16.778261  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55244
02/14/2018-16:03:48.766703  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59596
02/14/2018-15:56:00.132730  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58955
02/14/2018-15:58:10.749590  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61050
02/14/2018-16:10:24.954226  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49937
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:58105
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56291
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55852
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55366
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49349
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63373
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55955
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55898
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65018
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51544
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:62622
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57719
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49943
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:59421
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59223
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:64405
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51879
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:55244
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63818
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56737
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:48606
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:55930
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62953
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58955
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65228
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56228
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56260
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65477
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:25968
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:58701
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53056
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:56241
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55041
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61170
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59954
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54092
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49651
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:62923
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61050
02/14/2018-16:03:12.904694  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:52057
02/14/2018-16:10:44.157967  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61707
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62983
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53314
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:49599
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63806
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64829
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65324
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:51520
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58760
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:62234
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57145
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54223
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57140
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61549
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52224
02/14/2018-16:10:43.695013  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58084
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62022
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59596
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:58958
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51505
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54499
02/14/2018-16:10:44.765704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59270
02/14/2018-16:10:58.163428  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55925
02/14/2018-16:11:01.171599  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55925
02/14/2018-16:11:13.536917  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49736
02/14/2018-16:11:28.394977  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53597
02/14/2018-16:11:34.020293  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64018
02/14/2018-16:11:54.072492  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 113.161.67.190:54650 -> 172.31.64.111:445
02/14/2018-16:11:58.258959  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 113.161.67.190:55064 -> 172.31.64.111:445
02/14/2018-16:12:05.663457  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56972
02/14/2018-16:11:54.309454  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 113.161.67.190:54650 -> 172.31.64.111:445
02/14/2018-16:11:54.309454  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 113.161.67.190:54650 -> 172.31.64.111:445
02/14/2018-16:12:09.242335  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54673
02/14/2018-16:12:12.942368  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56971
02/14/2018-16:12:19.297455  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:49566
02/14/2018-16:12:19.838645  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58350
02/14/2018-16:12:27.742302  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53851
02/14/2018-16:12:46.397787  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57147
02/14/2018-16:13:01.705348  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55154
02/14/2018-16:13:04.809922  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59500
02/14/2018-16:13:10.596580  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 213.128.5.147:52516 -> 172.31.64.111:445
02/14/2018-16:13:14.688414  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 213.128.5.147:52939 -> 172.31.64.111:445
02/14/2018-16:13:10.815947  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 213.128.5.147:52516 -> 172.31.64.111:445
02/14/2018-16:13:10.815947  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 213.128.5.147:52516 -> 172.31.64.111:445
02/14/2018-16:14:01.528418  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63998
02/14/2018-16:14:02.448232  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63998
02/14/2018-16:14:00.392189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64197
02/14/2018-16:14:52.597669  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:54325
02/14/2018-16:14:38.510736  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 171.250.199.6:65519 -> 172.31.64.111:445
02/14/2018-16:14:53.321931  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:54325
02/14/2018-16:14:55.899730  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51938
02/14/2018-16:15:10.522512  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55306
02/14/2018-16:14:42.770649  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 171.250.199.6:49593 -> 172.31.64.111:445
02/14/2018-16:15:11.258988  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55306
02/14/2018-16:15:12.618358  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55306
02/14/2018-16:14:38.767043  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 171.250.199.6:65519 -> 172.31.64.111:445
02/14/2018-16:15:27.470813  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:53909
02/14/2018-16:14:38.767043  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 171.250.199.6:65519 -> 172.31.64.111:445
02/14/2018-16:15:28.086696  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:53909
02/14/2018-16:15:42.589433  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52870
02/14/2018-16:15:49.542723  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54657
02/14/2018-16:15:49.009476  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 38.84.134.54:51558 -> 172.31.64.111:445
02/14/2018-16:16:17.168937  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:63824
02/14/2018-16:16:26.531949  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58559
02/14/2018-16:15:43.871456  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 38.84.134.54:51011 -> 172.31.64.111:445
02/14/2018-16:16:45.790502  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51404
02/14/2018-16:16:14.755137  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57142
02/14/2018-16:16:46.535945  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61060
02/14/2018-16:15:44.274550  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 38.84.134.54:51011 -> 172.31.64.111:445
02/14/2018-16:15:44.274550  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 38.84.134.54:51011 -> 172.31.64.111:445
02/14/2018-16:17:41.919487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49249
02/14/2018-16:18:37.326089  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53822
02/14/2018-16:15:51.278346  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56574
02/14/2018-16:18:56.320745  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57663
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64676
02/14/2018-16:19:25.730848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52330
02/14/2018-16:19:33.048946  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58429
02/14/2018-16:19:07.360103  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52807
02/14/2018-16:19:43.987680  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57131
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61395
02/14/2018-16:17:37.291583  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61681
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54261
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56526
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57147
02/14/2018-16:17:39.422461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52425
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:56422
02/14/2018-16:12:24.360790  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57129
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59500
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:64018
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58350
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56972
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49736
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53597
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:49566
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55925
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:53851
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54673
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56971
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57147
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55154
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:61707
02/14/2018-16:15:18.481852  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49937
02/14/2018-16:20:28.539649  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63068
02/14/2018-16:20:32.115306  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:65215
02/14/2018-16:20:46.376754  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 91.237.182.72:60691 -> 172.31.64.111:445
02/14/2018-16:20:46.547923  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 91.237.182.72:60691 -> 172.31.64.111:445
02/14/2018-16:20:46.547923  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 91.237.182.72:60691 -> 172.31.64.111:445
02/14/2018-16:20:50.241183  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 91.237.182.72:61082 -> 172.31.64.111:445
02/14/2018-16:20:53.593133  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:51211
02/14/2018-16:20:58.220760  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:19147
02/14/2018-16:20:59.062595  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:19147
02/14/2018-16:21:12.878170  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:28454
02/14/2018-16:21:13.862866  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59343
02/14/2018-16:21:46.990679  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59228
02/14/2018-16:21:49.998786  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59228
02/14/2018-16:21:56.990579  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50461
02/14/2018-16:22:04.150771  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:65095
02/14/2018-16:22:19.665863  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55877
02/14/2018-16:23:09.030819  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4013
02/14/2018-16:23:14.766402  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59969
02/14/2018-16:22:59.595310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57909
02/14/2018-16:25:59.835634  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.69.8.2:52337 -> 172.31.64.111:445
02/14/2018-16:26:00.438268  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56764
02/14/2018-16:24:16.024721  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 171.250.199.6:60049 -> 172.31.64.111:445
02/14/2018-16:26:55.590020  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61185
02/14/2018-16:24:10.039405  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64391
02/14/2018-16:23:10.808114  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57113
02/14/2018-16:27:19.302735  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 178.219.88.9:33090 -> 172.31.64.111:445
02/14/2018-16:21:24.147912  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51328
02/14/2018-16:24:16.274077  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 171.250.199.6:60049 -> 172.31.64.111:445
02/14/2018-16:24:16.274077  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 171.250.199.6:60049 -> 172.31.64.111:445
02/14/2018-16:26:00.204704  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.69.8.2:52337 -> 172.31.64.111:445
02/14/2018-16:26:00.204704  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.69.8.2:52337 -> 172.31.64.111:445
02/14/2018-16:25:28.453224  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:52343
02/14/2018-16:23:02.437351  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49983
02/14/2018-16:28:20.138373  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:61795
02/14/2018-16:26:35.033686  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.137.9.242:53016 -> 172.31.64.111:445
02/14/2018-16:28:25.938053  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:52274 -> 172.31.64.111:445
02/14/2018-16:28:24.111278  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:51746 -> 172.31.64.111:445
02/14/2018-16:28:14.647184  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:59605
02/14/2018-16:24:20.274419  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 171.250.199.6:60487 -> 172.31.64.111:445
02/14/2018-16:28:28.895592  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:53160 -> 172.31.64.111:445
02/14/2018-16:27:15.521636  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 178.219.88.9:63246 -> 172.31.64.111:445
02/14/2018-16:25:05.421970  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52460
02/14/2018-16:27:15.677818  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 178.219.88.9:63246 -> 172.31.64.111:445
02/14/2018-16:27:15.677818  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 178.219.88.9:63246 -> 172.31.64.111:445
02/14/2018-16:28:39.393103  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:57367 -> 172.31.64.111:445
02/14/2018-16:28:22.397217  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:51149 -> 172.31.64.111:445
02/14/2018-16:28:31.048869  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:54482 -> 172.31.64.111:445
02/14/2018-16:26:04.608671  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.69.8.2:52810 -> 172.31.64.111:445
02/14/2018-16:28:27.412560  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54660
02/14/2018-16:24:50.997409  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57001
02/14/2018-16:28:09.452848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:63250
02/14/2018-16:28:37.221265  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:55974 -> 172.31.64.111:445
02/14/2018-16:26:38.844421  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64021
02/14/2018-16:26:31.110712  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 94.137.9.242:52671 -> 172.31.64.111:445
02/14/2018-16:26:31.293177  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.137.9.242:52671 -> 172.31.64.111:445
02/14/2018-16:26:31.293177  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 94.137.9.242:52671 -> 172.31.64.111:445
02/14/2018-16:21:53.881676  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:54659
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57663
02/14/2018-16:28:41.271832  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:59492 -> 172.31.64.111:445
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:58559
02/14/2018-16:26:37.443919  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57084
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:53909
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:54325
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54657
02/14/2018-16:27:51.447379  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49714
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57142
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49249
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51404
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63998
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:52870
02/14/2018-16:28:44.364889  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:61689 -> 172.31.64.111:445
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64197
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58429
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52425
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61681
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53822
02/14/2018-16:29:08.334489  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 176.103.90.202:51925 -> 172.31.64.111:445
02/14/2018-16:29:43.390618  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59866
02/14/2018-16:29:52.648384  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:61903
02/14/2018-16:30:02.707838  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57053
02/14/2018-16:30:02.313825  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:49738
02/14/2018-16:30:31.579062  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.139.166.170:50873 -> 172.31.64.111:445
02/14/2018-16:30:38.569667  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64356
02/14/2018-16:30:31.756079  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.139.166.170:50873 -> 172.31.64.111:445
02/14/2018-16:30:31.756079  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.139.166.170:50873 -> 172.31.64.111:445
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:63824
02/14/2018-16:30:39.161371  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 151.106.17.146:5464 -> 172.31.64.111:5060
02/14/2018-16:30:39.161371  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 151.106.17.146:5464 -> 172.31.64.111:5060
02/14/2018-16:31:33.706741  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52394
02/14/2018-16:28:46.869311  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 202.69.173.19:63071 -> 172.31.64.111:445
02/14/2018-16:31:59.245850  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63043
02/14/2018-16:32:16.034554  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:49818
02/14/2018-16:32:28.839821  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56842
02/14/2018-16:32:02.824212  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52297
02/14/2018-16:32:32.859829  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.121.34.167:55919 -> 172.31.64.111:445
02/14/2018-16:28:28.750678  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:65199
02/14/2018-16:32:13.015140  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54985
02/14/2018-16:33:23.996143  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61174
02/14/2018-16:33:51.022350  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59298
02/14/2018-16:32:28.820315  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 122.121.34.167:54902 -> 172.31.64.111:445
02/14/2018-16:30:15.530759  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61666
02/14/2018-16:34:35.492347  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:52598
02/14/2018-16:32:29.028159  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.121.34.167:54902 -> 172.31.64.111:445
02/14/2018-16:33:27.493310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57018
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51938
02/14/2018-16:33:45.836894  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:35999
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61060
02/14/2018-16:32:29.028159  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 122.121.34.167:54902 -> 172.31.64.111:445
02/14/2018-16:34:30.206840  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:38687
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52330
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56574
02/14/2018-16:34:59.532411  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:52967
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55306
02/14/2018-16:34:12.843448  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.111:44473 -> 172.31.64.111:41411
02/14/2018-16:34:19.050153  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65447
02/14/2018-16:33:20.191680  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:58102
02/14/2018-16:36:50.422863  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56975
02/14/2018-16:28:41.068823  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57113
02/14/2018-16:37:38.682026  [**] [1:2400019:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 20 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 191.101.167.99:50475 -> 172.31.64.111:3400
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64391
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:59228
02/14/2018-16:35:32.837055  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:55505
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59343
02/14/2018-16:30:35.530042  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.139.166.170:51282 -> 172.31.64.111:445
02/14/2018-16:28:47.633281  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54934
02/14/2018-16:37:04.607918  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62120
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:19147
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:65215
02/14/2018-16:36:58.956571  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 201.209.255.237:51451 -> 172.31.64.111:445
02/14/2018-16:36:59.097218  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 201.209.255.237:51451 -> 172.31.64.111:445
02/14/2018-16:36:59.097218  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 201.209.255.237:51451 -> 172.31.64.111:445
02/14/2018-16:37:59.618936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49801
02/14/2018-16:28:44.042299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4013
02/14/2018-16:36:44.554080  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:63331
02/14/2018-16:30:30.112169  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49543
02/14/2018-16:31:31.692254  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49990
02/14/2018-16:39:49.665912  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58199
02/14/2018-16:28:44.042299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63068
02/14/2018-16:40:13.717546  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56926
02/14/2018-16:40:44.300808  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62237
02/14/2018-16:40:59.311744  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.148.179.42:16802 -> 172.31.64.111:445
02/14/2018-16:28:44.042324  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51328
02/14/2018-16:38:54.762720  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54113
02/14/2018-16:28:41.068823  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:51211
02/14/2018-16:40:59.482003  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.148.179.42:16802 -> 172.31.64.111:445
02/14/2018-16:40:59.482003  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 177.148.179.42:16802 -> 172.31.64.111:445
02/14/2018-16:40:53.747923  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 119.46.141.6:12929 -> 172.31.64.111:445
02/14/2018-16:28:44.042299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50461
02/14/2018-16:40:54.014858  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 119.46.141.6:12929 -> 172.31.64.111:445
02/14/2018-16:40:54.014858  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 119.46.141.6:12929 -> 172.31.64.111:445
02/14/2018-16:41:00.560087  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54550
02/14/2018-16:34:53.534738  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 178.206.212.92:59084 -> 172.31.64.111:445
02/14/2018-16:28:41.068823  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:54659
02/14/2018-16:40:58.065813  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 119.46.141.6:3883 -> 172.31.64.111:445
02/14/2018-16:28:44.042337  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:52343
02/14/2018-16:35:14.172722  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53409
02/14/2018-16:41:12.125331  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59170
02/14/2018-16:37:25.804338  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56930
02/14/2018-16:42:03.805583  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 217.112.218.58:62106 -> 172.31.64.111:445
02/14/2018-16:21:42.678359  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:52807
02/14/2018-16:42:29.377893  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 14.142.181.2:53084 -> 172.31.64.111:445
02/14/2018-16:42:33.750041  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 14.142.181.2:53542 -> 172.31.64.111:445
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57909
02/14/2018-16:42:29.648492  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 14.142.181.2:53084 -> 172.31.64.111:445
02/14/2018-16:42:29.648492  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 14.142.181.2:53084 -> 172.31.64.111:445
02/14/2018-16:43:36.600935  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56873
02/14/2018-16:37:50.717155  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60130
02/14/2018-16:42:48.279149  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61543
02/14/2018-16:43:29.171946  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58795
02/14/2018-16:39:22.059172  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65401
02/14/2018-16:44:48.179853  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.69.8.2:52629 -> 172.31.64.111:445
02/14/2018-16:44:43.602176  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 103.69.8.2:52161 -> 172.31.64.111:445
02/14/2018-16:28:44.042278  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59969
02/14/2018-16:42:28.953248  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 217.112.218.58:64475 -> 172.31.64.111:445
02/14/2018-16:45:19.063469  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51044
02/14/2018-16:44:43.928731  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.69.8.2:52161 -> 172.31.64.111:445
02/14/2018-16:45:52.596545  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:36094
02/14/2018-16:46:14.099396  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55268
02/14/2018-16:28:44.042299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56764
02/14/2018-16:28:44.048430  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52460
02/14/2018-16:28:44.048430  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57084
02/14/2018-16:46:59.206353  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56816
02/14/2018-16:44:43.928731  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 103.69.8.2:52161 -> 172.31.64.111:445
02/14/2018-16:28:44.042324  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:65095
02/14/2018-16:28:44.048430  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57131
02/14/2018-16:46:22.547598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59159
02/14/2018-16:46:57.376178  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56374
02/14/2018-16:46:22.571598  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56856
02/14/2018-16:43:04.100213  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:52908
02/14/2018-16:28:44.042322  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:28454
02/14/2018-16:47:47.826594  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:51124
02/14/2018-16:28:44.048533  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64021
02/14/2018-16:48:03.731220  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63687
02/14/2018-16:39:17.671757  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:52519
02/14/2018-16:39:42.133660  [**] [1:2400000:2763] ET DROP Spamhaus DROP Listed Traffic Inbound group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 5.188.11.25:50794 -> 172.31.64.111:20772
02/14/2018-16:48:08.298251  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55769
02/14/2018-16:48:09.790695  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49772
02/14/2018-16:47:44.880666  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 124.66.154.38:4935 -> 172.31.64.111:3389
02/14/2018-16:48:16.400133  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58466
02/14/2018-16:29:17.937894  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51194
02/14/2018-16:48:52.420994  [**] [1:2402000:5577] ET DROP Dshield Block Listed Source group 1 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 89.248.168.14:65534 -> 172.31.64.111:8545
02/14/2018-16:49:53.107913  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55582
02/14/2018-16:49:33.698473  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52870
02/14/2018-16:44:24.166804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63155
02/14/2018-16:50:06.342810  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:58383
02/14/2018-16:49:57.388670  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56755
02/14/2018-16:29:35.714064  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53714
02/14/2018-16:46:46.932448  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60798
02/14/2018-16:50:47.520285  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59566
02/14/2018-16:47:00.461297  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62377
02/14/2018-16:34:49.390312  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 178.206.212.92:58641 -> 172.31.64.111:445
02/14/2018-16:50:21.888336  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56756
02/14/2018-16:36:09.255012  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57764
02/14/2018-16:34:49.657059  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 178.206.212.92:58641 -> 172.31.64.111:445
02/14/2018-16:34:49.657059  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 178.206.212.92:58641 -> 172.31.64.111:445
02/14/2018-16:47:11.516870  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56031
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55877
02/14/2018-16:49:23.761762  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63499
02/14/2018-16:35:38.508148  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49928
02/14/2018-16:50:58.270024  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.88.162.147:64508 -> 172.31.64.111:445
02/14/2018-16:28:44.042277  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57001
02/14/2018-16:50:58.946663  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.88.162.147:64508 -> 172.31.64.111:445
02/14/2018-16:41:44.455669  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:20193
02/14/2018-16:38:49.370706  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5101 -> 172.31.64.111:5060
02/14/2018-16:38:49.370706  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 212.47.252.61:5101 -> 172.31.64.111:5060
02/14/2018-16:50:53.934882  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.88.162.147:63695 -> 172.31.64.111:445
02/14/2018-16:43:55.875555  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:60287
02/14/2018-16:39:13.082204  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63925
02/14/2018-16:50:54.137034  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.88.162.147:63695 -> 172.31.64.111:445
02/14/2018-16:50:54.137034  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.88.162.147:63695 -> 172.31.64.111:445
02/14/2018-16:44:35.637413  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52171
02/14/2018-16:48:58.384740  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51413
02/14/2018-16:42:34.181628  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54440
02/14/2018-16:29:04.499677  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 176.103.90.202:51504 -> 172.31.64.111:445
02/14/2018-16:29:04.673730  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 176.103.90.202:51504 -> 172.31.64.111:445
02/14/2018-16:29:04.673730  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 176.103.90.202:51504 -> 172.31.64.111:445
02/14/2018-16:31:05.579028  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.47.104.216:58427 -> 172.31.64.111:445
02/14/2018-16:41:03.162449  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 177.148.179.42:31042 -> 172.31.64.111:445
02/14/2018-16:30:38.077656  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49642
02/14/2018-16:44:00.432985  [**] [1:2008578:4] ET SCAN Sipvicious Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5114 -> 172.31.64.111:5060
02/14/2018-16:44:00.432985  [**] [1:2011716:3] ET SCAN Sipvicious User-Agent Detected (friendly-scanner) [**] [Classification: Attempted Information Leak] [Priority: 2] {UDP} 46.166.142.60:5114 -> 172.31.64.111:5060
02/14/2018-16:47:08.931376  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59359
02/14/2018-16:31:01.742369  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.47.104.216:58039 -> 172.31.64.111:445
02/14/2018-16:31:01.909628  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.47.104.216:58039 -> 172.31.64.111:445
02/14/2018-16:31:01.909628  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.47.104.216:58039 -> 172.31.64.111:445
02/14/2018-16:32:09.688844  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 218.78.186.242:65199
02/14/2018-16:37:02.622841  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 201.209.255.237:52229 -> 172.31.64.111:445
02/14/2018-16:37:02.302781  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:61795
02/14/2018-16:28:44.042299  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49983
02/14/2018-16:41:39.040738  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49994
02/14/2018-16:41:38.805978  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59866
02/14/2018-16:41:39.273254  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54934
02/14/2018-16:37:02.758136  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:63250
02/14/2018-16:51:42.232004  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63780
02/14/2018-16:41:46.879180  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60264
02/14/2018-16:41:47.608960  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60264
02/14/2018-16:41:46.879180  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:61903
02/14/2018-16:51:53.532572  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:60791
02/14/2018-16:41:41.216589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53714
02/14/2018-16:51:44.391992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63733
02/14/2018-16:41:41.216589  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:59605
02/14/2018-16:41:48.984365  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51194
02/14/2018-16:41:46.647704  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49714
02/14/2018-16:46:04.652575  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49229
02/14/2018-16:52:36.932333  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51620
02/14/2018-16:52:26.474442  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.251.5.4:53108 -> 172.31.64.111:445
02/14/2018-16:53:14.084091  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 80.67.220.61:58392 -> 172.31.64.111:445
02/14/2018-16:34:34.869535  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61185
02/14/2018-16:53:14.289196  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 80.67.220.61:58392 -> 172.31.64.111:445
02/14/2018-16:53:14.289196  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 80.67.220.61:58392 -> 172.31.64.111:445
02/14/2018-16:53:18.118975  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 80.67.220.61:58810 -> 172.31.64.111:445
02/14/2018-16:49:57.348060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52297
02/14/2018-16:49:57.348060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:65401
02/14/2018-16:49:57.348060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56031
02/14/2018-16:53:33.173743  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54336
02/14/2018-16:53:31.743212  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55845
02/14/2018-16:49:57.348060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65447
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54113
02/14/2018-16:53:44.199404  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56692
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57053
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56975
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61543
02/14/2018-16:53:53.083452  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60439
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:20193
02/14/2018-16:49:57.348060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:52519
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57018
02/14/2018-16:54:23.329645  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:51871
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63043
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62237
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:35999
02/14/2018-16:52:22.136868  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 180.251.5.4:52679 -> 172.31.64.111:445
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61174
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63155
02/14/2018-16:52:22.395218  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.251.5.4:52679 -> 172.31.64.111:445
02/14/2018-16:55:21.051586  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64338
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:58102
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:52598
02/14/2018-16:55:20.673554  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61309
02/14/2018-16:52:22.395218  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 180.251.5.4:52679 -> 172.31.64.111:445
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:49818
02/14/2018-16:56:07.806936  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49902
02/14/2018-16:56:15.632572  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52133
02/14/2018-16:54:53.034553  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.241.16.109:61512 -> 172.31.64.111:445
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59359
02/14/2018-16:54:56.904330  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.241.16.109:61914 -> 172.31.64.111:445
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 176.213.37.52:49738
02/14/2018-16:54:26.403642  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60131
02/14/2018-16:54:53.204036  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.241.16.109:61512 -> 172.31.64.111:445
02/14/2018-16:54:53.204036  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.241.16.109:61512 -> 172.31.64.111:445
02/14/2018-16:57:10.468915  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56518
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58199
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63925
02/14/2018-16:55:56.890803  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60788
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54550
02/14/2018-16:57:06.094836  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56622
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52171
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58795
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54985
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:63331
02/14/2018-16:53:59.106987  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:49823 -> 172.31.64.111:3389
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:51124
02/14/2018-16:51:15.225124  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59170
02/14/2018-16:54:02.048109  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:49823 -> 172.31.64.111:3389
02/14/2018-16:57:07.993921  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51906
02/14/2018-16:56:30.407281  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:49406
02/14/2018-16:54:07.977143  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:49823 -> 172.31.64.111:3389
02/14/2018-16:51:15.225124  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60798
02/14/2018-16:59:23.087138  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:59890
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49801
02/14/2018-16:58:15.812487  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56379
02/14/2018-16:58:04.387967  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51856
02/14/2018-16:56:26.513850  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63042
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:62377
02/14/2018-16:51:15.333808  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56842
02/14/2018-16:58:05.099714  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51856
02/14/2018-16:55:03.938006  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63946
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:60130
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 185.107.45.71:52908
02/14/2018-16:51:17.716461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55268
02/14/2018-16:58:55.797541  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53473
02/14/2018-16:58:55.442440  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58870
02/14/2018-16:51:17.732658  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56856
02/14/2018-16:57:13.094076  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55104
02/14/2018-16:51:17.716461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56816
02/14/2018-16:58:56.673761  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:58985
02/14/2018-16:51:17.828197  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59298
02/14/2018-16:56:51.118840  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64152
02/14/2018-16:37:02.173240  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54660
02/14/2018-17:01:39.929747  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49852
02/14/2018-16:51:15.225124  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56926
02/14/2018-16:51:19.455955  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49543
02/14/2018-16:51:15.313224  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62120
02/14/2018-16:51:15.342960  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:56374
02/14/2018-16:51:17.716423  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:36094
02/14/2018-16:51:18.026441  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51044
02/14/2018-16:59:54.815434  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53649
02/14/2018-16:58:05.097327  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60855
02/14/2018-16:51:17.716461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59159
02/14/2018-17:01:54.094026  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62432
02/14/2018-17:01:46.509227  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50012
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64356
02/14/2018-17:01:47.125255  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50012
02/14/2018-17:01:44.582658  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62278
02/14/2018-17:01:48.250236  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50012
02/14/2018-17:01:35.189684  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54973
02/14/2018-16:51:15.249140  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 145.239.165.150:55505
02/14/2018-16:51:17.716423  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49928
02/14/2018-16:51:17.526912  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:52967
02/14/2018-17:00:28.394398  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57427
02/14/2018-16:58:59.960787  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65348
02/14/2018-16:59:41.270809  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:57245
02/14/2018-16:59:58.532421  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54738
02/14/2018-16:51:17.716461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:60287
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:60264
02/14/2018-16:51:15.249160  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56873
02/14/2018-16:50:32.311044  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:49229
02/14/2018-17:00:49.621552  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58059
02/14/2018-16:51:17.526912  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49990
02/14/2018-16:54:28.620028  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55725
02/14/2018-16:51:15.237664  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49642
02/14/2018-16:51:17.716461  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52394
02/14/2018-16:54:31.620787  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55725
02/14/2018-16:51:17.716423  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53409
02/14/2018-16:59:26.148607  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56319
02/14/2018-16:51:17.621398  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49994
02/14/2018-16:54:31.849220  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:58383
02/14/2018-16:51:17.828197  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61666
02/14/2018-17:01:58.777601  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57601
02/14/2018-17:00:38.357937  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64418
02/14/2018-17:01:33.207214  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54627
02/14/2018-16:56:17.284674  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:55769
02/14/2018-17:02:39.222171  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49973
02/14/2018-16:51:17.526912  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54440
02/14/2018-16:56:17.284674  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56755
02/14/2018-16:51:18.026480  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:38687
02/14/2018-17:02:52.051158  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64067
02/14/2018-17:02:52.623627  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64067
02/14/2018-17:00:46.807854  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:49239
02/14/2018-16:51:15.345041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56930
02/14/2018-17:03:29.807735  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 189.18.86.12:58580 -> 172.31.64.111:445
02/14/2018-17:03:30.374382  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 189.18.86.12:58580 -> 172.31.64.111:445
02/14/2018-17:03:30.374382  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 189.18.86.12:58580 -> 172.31.64.111:445
02/14/2018-17:03:49.641220  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57636
02/14/2018-16:57:06.550969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55582
02/14/2018-17:00:42.090093  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49454
02/14/2018-16:57:06.550969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49772
02/14/2018-16:57:06.550969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:63499
02/14/2018-17:02:29.065060  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56437
02/14/2018-17:04:17.216645  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63400
02/14/2018-17:03:34.206785  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54073
02/14/2018-17:03:34.409144  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 189.18.86.12:59190 -> 172.31.64.111:445
02/14/2018-16:51:17.932183  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57764
02/14/2018-16:56:17.284674  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51413
02/14/2018-17:03:59.242232  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:62128
02/14/2018-16:57:06.550969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63687
02/14/2018-16:57:06.550969  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58466
02/14/2018-17:04:28.981819  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58176
02/14/2018-17:02:30.939774  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53548
02/14/2018-17:04:22.546156  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:55751
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51906
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63042
02/14/2018-16:56:17.284674  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:52870
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:51871
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:55845
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56379
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56518
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:63946
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60788
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63733
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56756
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56622
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:59566
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60855
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:60439
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55104
02/14/2018-17:01:48.151253  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:64152
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52133
02/14/2018-17:00:51.831189  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:60791
02/14/2018-17:01:48.151253  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:49406
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:55725
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:51856
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60131
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54336
02/14/2018-17:01:48.151253  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:61309
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:51620
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:63780
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:64338
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.27:49902
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56692
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58870
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53473
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53649
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65348
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56319
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:59890
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:58985
02/14/2018-17:01:59.603015  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:57245
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:49239
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49973
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62278
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57427
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:56437
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58059
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:54973
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:50012
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49852
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54627
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64418
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:53548
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:54738
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:49454
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:62432
02/14/2018-17:04:45.085310  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57601
02/14/2018-17:05:03.546888  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.92.4.111:60597 -> 172.31.64.111:445
02/14/2018-17:05:03.647353  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.92.4.111:60597 -> 172.31.64.111:445
02/14/2018-17:05:03.647353  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.92.4.111:60597 -> 172.31.64.111:445
02/14/2018-17:05:07.056079  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.92.4.111:60949 -> 172.31.64.111:445
02/14/2018-17:05:23.805409  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62449
02/14/2018-17:05:31.579039  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4450
02/14/2018-17:05:50.364628  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 80.252.136.221:56205 -> 172.31.64.111:445
02/14/2018-17:05:50.504456  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 80.252.136.221:56205 -> 172.31.64.111:445
02/14/2018-17:05:50.504456  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 80.252.136.221:56205 -> 172.31.64.111:445
02/14/2018-17:05:54.063859  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 80.252.136.221:56592 -> 172.31.64.111:445
02/14/2018-17:06:03.718592  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53992
02/14/2018-17:06:18.345008  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50049
02/14/2018-17:05:49.345647  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:64067
02/14/2018-17:05:52.222577  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54073
02/14/2018-17:05:52.222577  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57636
02/14/2018-17:07:12.950511  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54203
02/14/2018-17:07:10.294900  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57549
02/14/2018-17:07:50.378030  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60941
02/14/2018-17:08:07.890777  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58341
02/14/2018-17:06:56.560990  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:55751
02/14/2018-17:06:56.560990  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:62128
02/14/2018-17:06:56.560990  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:63400
02/14/2018-17:08:36.346963  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63442
02/14/2018-17:09:02.468102  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62303
02/14/2018-17:09:23.012125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:59869
02/14/2018-17:07:16.592551  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58176
02/14/2018-17:09:37.243970  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51520
02/14/2018-17:07:36.617653  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.165.6.48:4450
02/14/2018-17:07:36.617653  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62449
02/14/2018-17:09:46.754165  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50049
02/14/2018-17:09:46.754165  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54203
02/14/2018-17:09:46.754165  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57549
02/14/2018-17:09:46.754165  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53992
02/14/2018-17:09:57.304722  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50109
02/14/2018-17:10:31.213956  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57459
02/14/2018-17:10:28.580783  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 114.26.90.191:59799 -> 172.31.64.111:445
02/14/2018-17:10:32.592681  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 114.26.90.191:60193 -> 172.31.64.111:445
02/14/2018-17:10:28.798272  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 114.26.90.191:59799 -> 172.31.64.111:445
02/14/2018-17:10:28.798272  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 114.26.90.191:59799 -> 172.31.64.111:445
02/14/2018-17:10:41.079725  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.67.23.86:59591 -> 172.31.64.111:445
02/14/2018-17:10:37.253518  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 186.67.23.86:59220 -> 172.31.64.111:445
02/14/2018-17:10:51.776777  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54127
02/14/2018-17:10:37.417494  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.67.23.86:59220 -> 172.31.64.111:445
02/14/2018-17:10:37.417494  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 186.67.23.86:59220 -> 172.31.64.111:445
02/14/2018-17:11:01.562415  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:43242
02/14/2018-17:11:00.616490  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57131
02/14/2018-17:11:23.230680  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58466
02/14/2018-17:11:10.991355  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:57777
02/14/2018-17:11:27.645855  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57475
02/14/2018-17:10:16.758273  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60941
02/14/2018-17:11:46.405803  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58182
02/14/2018-17:11:54.583271  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.103.66.1:32045 -> 172.31.64.111:445
02/14/2018-17:11:51.007006  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 187.103.66.1:41363 -> 172.31.64.111:445
02/14/2018-17:11:51.116830  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.103.66.1:41363 -> 172.31.64.111:445
02/14/2018-17:11:51.116830  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 187.103.66.1:41363 -> 172.31.64.111:445
02/14/2018-17:10:53.769012  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58341
02/14/2018-17:12:41.003382  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62419
02/14/2018-17:11:27.937411  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:59869
02/14/2018-17:11:27.937411  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62303
02/14/2018-17:11:36.882445  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63442
02/14/2018-17:13:09.550278  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65410
02/14/2018-17:13:25.027059  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:62434
02/14/2018-17:13:35.724707  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50214
02/14/2018-17:13:52.115152  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57361
02/14/2018-17:14:01.691799  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:63749
02/14/2018-17:14:06.008941  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:64245
02/14/2018-17:14:44.142335  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:56989
02/14/2018-17:14:55.830956  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55981
02/14/2018-17:15:24.519659  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58173
02/14/2018-17:15:25.424017  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53897
02/14/2018-17:15:40.640476  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:54313
02/14/2018-17:15:51.263580  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 106.2.89.7:60003 -> 172.31.64.111:445
02/14/2018-17:12:36.956831  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:51520
02/14/2018-17:15:51.710835  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 106.2.89.7:60003 -> 172.31.64.111:445
02/14/2018-17:15:51.710835  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 106.2.89.7:60003 -> 172.31.64.111:445
02/14/2018-17:16:40.848488  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62921
02/14/2018-17:16:18.873995  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62256
02/14/2018-17:16:29.196612  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 41.68.216.211:62552 -> 172.31.64.111:445
02/14/2018-17:17:13.346164  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49863
02/14/2018-17:14:30.153515  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54239
02/14/2018-17:12:06.941885  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50109
02/14/2018-17:15:56.492283  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 106.2.89.7:60513 -> 172.31.64.111:445
02/14/2018-17:17:11.879010  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57257
02/14/2018-17:18:07.996388  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54132
02/14/2018-17:12:46.957840  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57459
02/14/2018-17:16:20.780522  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 41.68.216.211:61135 -> 172.31.64.111:445
02/14/2018-17:16:22.202969  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 41.68.216.211:61135 -> 172.31.64.111:445
02/14/2018-17:16:22.202969  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 41.68.216.211:61135 -> 172.31.64.111:445
02/14/2018-17:12:57.051711  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54127
02/14/2018-17:13:06.971130  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:43242
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54239
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:57475
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:58466
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:65410
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:62434
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:64245
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:63749
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:57131
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:57777
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62419
02/14/2018-17:18:16.351761  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:54313
02/14/2018-17:18:16.351761  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55981
02/14/2018-17:16:43.236637  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50214
02/14/2018-17:18:16.732995  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58173
02/14/2018-17:18:16.732995  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:53897
02/14/2018-17:18:16.732995  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 207.246.95.116:56989
02/14/2018-17:18:13.726125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58182
02/14/2018-17:18:16.077992  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57361
02/14/2018-17:18:25.489552  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:57617 -> 172.31.64.111:3389
02/14/2018-17:18:28.436304  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:57617 -> 172.31.64.111:3389
02/14/2018-17:18:34.460632  [**] [1:2014384:8] ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 176.213.37.52:57617 -> 172.31.64.111:3389
02/14/2018-17:18:25.485705  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53491
02/14/2018-17:19:03.140041  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58274
02/14/2018-17:19:23.436358  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54539
02/14/2018-17:19:33.886743  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:55037
02/14/2018-17:20:07.687866  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60425
02/14/2018-17:20:13.814833  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 185.23.131.14:62299 -> 172.31.64.111:445
02/14/2018-17:20:32.366414  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57149
02/14/2018-17:20:51.974709  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50136
02/14/2018-17:19:57.622171  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62389
02/14/2018-17:21:51.630108  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54849
02/14/2018-17:21:46.422254  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54295
02/14/2018-17:20:09.732880  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 185.23.131.14:61845 -> 172.31.64.111:445
02/14/2018-17:20:09.948598  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 185.23.131.14:61845 -> 172.31.64.111:445
02/14/2018-17:20:09.948598  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 185.23.131.14:61845 -> 172.31.64.111:445
02/14/2018-17:22:05.787768  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53607
02/14/2018-17:22:06.456502  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53607
02/14/2018-17:22:32.111638  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59470
02/14/2018-17:22:40.682316  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58522
02/14/2018-17:23:11.376250  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:2513
02/14/2018-17:22:41.780847  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56139
02/14/2018-17:23:56.309882  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:7966
02/14/2018-17:23:07.494980  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:52550
02/14/2018-17:25:23.810689  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54371
02/14/2018-17:22:29.859430  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:55987
02/14/2018-17:26:44.494864  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55407
02/14/2018-17:23:52.227266  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57034
02/14/2018-17:23:29.177587  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57923
02/14/2018-17:25:35.682000  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64654
02/14/2018-17:26:58.561627  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 77.43.201.127:62137 -> 172.31.64.111:445
02/14/2018-17:23:35.391661  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62704
02/14/2018-17:27:10.523975  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56918
02/14/2018-17:26:58.752045  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 77.43.201.127:62137 -> 172.31.64.111:445
02/14/2018-17:26:58.752045  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 77.43.201.127:62137 -> 172.31.64.111:445
02/14/2018-17:24:06.429971  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58826
02/14/2018-17:24:06.956383  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58826
02/14/2018-17:26:59.135045  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.77.42.90:60177 -> 172.31.64.111:445
02/14/2018-17:27:12.371903  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:61866
02/14/2018-17:27:02.547878  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 77.43.201.127:62580 -> 172.31.64.111:445
02/14/2018-17:24:00.118758  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53839
02/14/2018-17:27:32.100311  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:64276
02/14/2018-17:21:48.109194  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50994
02/14/2018-17:26:54.877262  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:64591
02/14/2018-17:30:13.796556  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.78.124.29:54500 -> 172.31.64.111:445
02/14/2018-17:23:13.169085  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58577
02/14/2018-17:30:14.176559  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.78.124.29:54500 -> 172.31.64.111:445
02/14/2018-17:30:14.176559  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 36.78.124.29:54500 -> 172.31.64.111:445
02/14/2018-17:24:41.340966  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:14280
02/14/2018-17:24:42.056472  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:14280
02/14/2018-17:29:59.986692  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52886
02/14/2018-17:30:28.852736  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56802
02/14/2018-17:29:00.619073  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53616
02/14/2018-17:26:55.449579  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 190.77.42.90:59753 -> 172.31.64.111:445
02/14/2018-17:26:55.595157  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.77.42.90:59753 -> 172.31.64.111:445
02/14/2018-17:26:55.595157  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 190.77.42.90:59753 -> 172.31.64.111:445
02/14/2018-17:31:04.456909  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 85.98.45.109:63512 -> 172.31.64.111:445
02/14/2018-17:24:42.840848  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:51293
02/14/2018-17:31:07.292538  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:50404
02/14/2018-17:31:04.671098  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 85.98.45.109:63512 -> 172.31.64.111:445
02/14/2018-17:31:04.671098  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 85.98.45.109:63512 -> 172.31.64.111:445
02/14/2018-17:30:18.528395  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 36.78.124.29:55034 -> 172.31.64.111:445
02/14/2018-17:27:12.372117  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62553
02/14/2018-17:31:13.948550  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51015
02/14/2018-17:24:29.473032  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50396
02/14/2018-17:29:55.024583  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57415
02/14/2018-17:28:06.626560  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49902
02/14/2018-17:31:32.522677  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 220.137.5.221:57707 -> 172.31.64.111:445
02/14/2018-17:31:08.443495  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 85.98.45.109:63916 -> 172.31.64.111:445
02/14/2018-17:29:44.875831  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:56038
02/14/2018-17:28:21.820577  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62331
02/14/2018-17:30:51.549104  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58018
02/14/2018-17:30:54.556795  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58018
02/14/2018-17:31:39.037980  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:49165
02/14/2018-17:29:34.501108  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54985
02/14/2018-17:31:43.740736  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65407
02/14/2018-17:31:37.431991  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59812
02/14/2018-17:25:07.432582  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64849
02/14/2018-17:30:49.713206  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61265
02/14/2018-17:26:18.087248  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58490
02/14/2018-17:32:25.339125  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63199
02/14/2018-17:32:37.697435  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52824
02/14/2018-17:32:49.809309  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49749
02/14/2018-17:33:15.248906  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50358
02/14/2018-17:33:19.805815  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 31.42.116.69:49334 -> 172.31.64.111:445
02/14/2018-17:33:32.057132  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57149
02/14/2018-17:32:40.899418  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.241.16.109:49671 -> 172.31.64.111:445
02/14/2018-17:33:46.261933  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56683
02/14/2018-17:34:05.179334  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57275
02/14/2018-17:34:26.429887  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61284
02/14/2018-17:32:36.965789  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 95.241.16.109:49269 -> 172.31.64.111:445
02/14/2018-17:32:37.197935  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.241.16.109:49269 -> 172.31.64.111:445
02/14/2018-17:32:37.197935  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 95.241.16.109:49269 -> 172.31.64.111:445
02/14/2018-17:34:53.741296  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57287
02/14/2018-17:36:14.902521  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53179
02/14/2018-17:35:33.611316  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:38437
02/14/2018-17:35:34.198526  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:38437
02/14/2018-17:37:08.662260  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56919
02/14/2018-17:31:28.484301  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 220.137.5.221:57270 -> 172.31.64.111:445
02/14/2018-17:33:41.913158  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.218.40.59:56574 -> 172.31.64.111:445
02/14/2018-17:31:28.693890  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 220.137.5.221:57270 -> 172.31.64.111:445
02/14/2018-17:31:28.693890  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 220.137.5.221:57270 -> 172.31.64.111:445
02/14/2018-17:37:58.075503  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:57960
02/14/2018-17:33:42.099878  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.218.40.59:56574 -> 172.31.64.111:445
02/14/2018-17:33:42.099878  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 89.218.40.59:56574 -> 172.31.64.111:445
02/14/2018-17:37:03.542718  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56561
02/14/2018-17:35:32.650804  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59149
02/14/2018-17:38:02.855527  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60803
02/14/2018-17:35:59.333337  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:49895
02/14/2018-17:33:16.044410  [**] [1:2102465:9] GPL NETBIOS SMB-DS IPC$ share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 31.42.116.69:65330 -> 172.31.64.111:445
02/14/2018-17:33:16.199348  [**] [1:2025649:2] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 31.42.116.69:65330 -> 172.31.64.111:445
02/14/2018-17:33:16.199348  [**] [1:2025992:1] ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (Generic Flags) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 31.42.116.69:65330 -> 172.31.64.111:445
02/14/2018-17:35:59.906780  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53646
02/14/2018-17:35:20.786154  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49175
02/14/2018-17:35:33.468204  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:53564
02/14/2018-17:36:31.453855  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64208
02/14/2018-17:33:45.876709  [**] [1:2102466:9] GPL NETBIOS SMB-DS IPC$ unicode share access [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 89.218.40.59:56961 -> 172.31.64.111:445
02/14/2018-17:38:08.678541  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54756
02/14/2018-17:24:27.026315  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:57673
02/14/2018-17:31:55.806431  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:14867
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:64591
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62389
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:7966
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:55407
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57415
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58522
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54132
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49902
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54295
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49863
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 202.181.206.254:56038
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56918
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:55037
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:59470
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50994
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:54371
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58274
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62256
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:57673
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:64654
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62331
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:54849
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54539
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62704
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57149
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57923
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57257
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:52886
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53839
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:2513
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:62921
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50396
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:53607
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:62553
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:50136
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:60425
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53616
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64849
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:56139
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:57034
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 58.185.29.178:61866
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:58490
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:14280
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:55987
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56802
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:53491
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:54985
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:52550
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58826
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.21:64276
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 193.19.118.97:51293
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.116.6:58577
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 201.174.154.14:50404
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:59812
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:50358
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:63199
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61284
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:49895
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:57275
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56561
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 211.234.94.205:56683
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 206.47.141.237:49749
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:61265
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:49175
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:57960
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 152.101.118.11:51015
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.115.177:53646
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 180.179.21.221:59149
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:54756
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:38437
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:56919
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:65407
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 89.248.166.116:53564
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:52824
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:57287
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:60803
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 212.92.105.107:14867
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:57149
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 175.195.219.31:64208
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 183.134.62.162:53179
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 12.12.144.38:49165
02/14/2018-17:32:46.713259  [**] [1:2001330:8] ET POLICY RDP connection confirm [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.31.64.111:3389 -> 77.243.191.23:58018
"""

file = open("fast.log", "w+")
file.write(input)

s3_client.upload_file("./fast.log", bucket, req_log_store)

request_body = {"object_key": req_log_store}

#Serialize data for endpoint
data = json.loads(json.dumps(request_body))
payload = json.dumps(data)

json.dump(data, open("req.json", "w+"))

s3_client.upload_file("req.json", bucket, req_json_store)

s3_req_location = "s3://technique-sagemaker-v1/request/req.json"

result = runtime_sm_client.invoke_endpoint_async(
	EndpointName = endpoint_name,
	ContentType=content_type,
	InputLocation=s3_req_location
)

print(result)
if(not str(result["ResponseMetadata"]["HTTPStatusCode"]).startswith("2")):
	print("Got non 200 response")
	raise("Got non 200 response")
else:
	print("Got 200 response. wait for the output object to be created.")


# Load data from s3
s3_output_bucket, s3_output_object = split_s3_path(result["OutputLocation"])
print(f"s3 output bucket : {s3_output_bucket}")
print(f"s3 output object : {s3_output_object}")

while True:
	try:
		s3_client.head_object(Bucket = s3_output_bucket, Key = s3_output_object)
		print("Output object created.")
		break
	except Exception as e:
		print(e)
		print("Output object not created yet")
		time.sleep(60)


s3_client.download_file(s3_output_bucket, s3_output_object, "out.json")
print("Downloaded output object")

print("Read json file")
result = json.load(open("out.json"))
print(result)
