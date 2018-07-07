# TLS Analyzer

This Go software takes a pcap network capture as input, analyzes it and outputs some numbers about TLS version and used ciphers, e.g.:

```
145876 packets analyzed. Here are the results:

TLS versions offered by clients (in CLIENT_HELLO)
TLS 1.0:                24
TLS 1.1:                0
TLS 1.2:                1846

TLS versions announced by server (in SERVER_HELLO)
TLS 1.0:                0
TLS 1.1:                0
TLS 1.2:                1936

=== Ciphers supported by clients: ===
TLS_DHE_RSA_WITH_AES_256_CCM                        28
TLS_DHE_DSS_WITH_AES_256_CBC_SHA                    459
TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA                45
TLS_RSA_WITH_AES_128_CCM                            28
TLS_DHE_RSA_WITH_AES_256_CCM_8                      20
TLS_DH_RSA_WITH_AES_128_CBC_SHA256                  21
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                    3
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384               1622
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256         1070
[...]


=== Ciphers announced by server: ===
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             26
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256           1
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       3
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             1
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             1285
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           418
TLS_DHE_RSA_WITH_AES_256_CBC_SHA                202
```

## Usage 

1. Record a network dump using netdump\
    E.g. for XMPP (port 5222): ```tcpdump port 5222 -i eth0 -w tcpdump.pcap```
2. Feed the network dump into the analyzer:\
    ```./analyzer -d tcpdump.pcap```



## Development

This is not considered a very stable, rock solid tool. If you'd like to improve the code and make it more reliable / robust, go ahead and submit a pull request! :-)

### To do

* Sorting of all result tables according to count
