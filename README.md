# ebpf-ssl-interceptor
ebpf-ssl-interceptor

## client

```
curl -k https://example.com:5000/?user=kalai
```
## server
```
  context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2 )
 * Debugger is active!
 * Debugger PIN: 959-545-977
127.0.0.1 - - [10/May/2024 12:33:18] "GET /?user=kalai HTTP/1.1" 200 -
```
## output
./cilium-ebpf 
```
2024/05/10 12:44:24 Waiting for events..
2024/05/10 12:44:28 ===================================================
2024/05/10 12:44:28 Pid: 61364 
2024/05/10 12:44:28 Traffic  sent
 
2024/05/10 12:44:28 Data: GET /?user=kalai HTTP/1.1
Host: example.com:5000
User-Agent: curl/7.81.0
Accept: */*


2024/05/10 12:44:28 ===================================================
2024/05/10 12:44:28 ===================================================
2024/05/10 12:44:28 Pid: 61364 
2024/05/10 12:44:28 Traffic  recieved
 
2024/05/10 12:44:28 Data: HTTP/1.1 200 OK
Server: Werkzeug/2.3.4 Python/3.10.12
Date: Fri, 10 May 2024 12:44:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13
Connection: close


2024/05/10 12:44:28 ===================================================
2024/05/10 12:44:28 ===================================================
2024/05/10 12:44:28 Pid: 61364 
2024/05/10 12:44:28 Traffic  recieved
 
2024/05/10 12:44:28 Data: Hello, kalai!OK
Server: Werkzeug/2.3.4 Python/3.10.12
Date: Fri, 10 May 2024 12:44:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13
Connection: close


2024/05/10 12:44:28 ===================================================

```
