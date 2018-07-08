# TLSStats

This Go software takes a pcap network capture as input, analyzes it and outputs some numbers about TLS version and used ciphers, e.g.:

```
145876 packets analyzed. Here are the results:

=== TLS versions supported by clients ===
TLS 1.2       1846
TLS 1.0       24

=== TLS versions chosen by server ===
TLS 1.2       1936

=== Ciphers supported by clients: ===
TLS_RSA_WITH_AES_128_CBC_SHA                        1866
TLS_RSA_WITH_AES_256_CBC_SHA                        1866
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA                1865
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA                1865
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                  1865
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                  1865
TLS_RSA_WITH_3DES_EDE_CBC_SHA                       1748
[...]

=== Ciphers chosen by server ===
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             1285
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           418
TLS_DHE_RSA_WITH_AES_256_CBC_SHA                202
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             26
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       3
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256           1
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             1

=== TLS alerts ===
BAD_RECORD_MAC               46
PROTOCOL_VERSION             25
[UNKNOWN ALERT 0x000A]       4
INTERNAL_ERROR               2
```


## Usage 

1. Download or compile Tool. Downloads for Linux x86_64 available [here](https://github.com/ThomasLeister/tlsstats/releases)
2. Record a network dump using ```tcpdump```\
    E.g. for information on XMPP client connections (port 5222):\
    ```tcpdump port 5222 -i eth0 -w tcpdump.pcap```
3. Feed the network dump into the analyzer:\
    ```./tlsstats -d tcpdump.pcap```



## Development

This is not considered a very stable, rock solid tool. If you'd like to improve the code and make it more reliable / robust, go ahead and submit a pull request! :-)
