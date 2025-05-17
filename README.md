# PXE Boot Server

## Build the docker image

```bash
docker build -t pxe-boot-server .
```

## Run the docker image

```bash
docker run --rm -it --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  -v /path/to/your/tftpboot:/var/lib/tftpboot \
  -v /path/to/your/dnsmasq.conf:/etc/dnsmasq.conf \
  pxe-boot-server
```