## Capture network DNS traffic and display the answers.

This is part of the ip.thc.org project.

```sh
curl -o dnsstream -SsfL https://github.com/SkyperTHC/dnsstream/releases/latest/download/dnsstream_linux-$(uname -m) \
&& chmod 755 dnsstream
```

```sh
./dnsstream eth0
```

```sh
./dnsstream file.pcap
```
