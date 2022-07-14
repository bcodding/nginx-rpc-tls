# ningx-rpc-tls
An nginx module to offload TLS for RPC.

## How to build

Follow the [nginx instructions to compile modules](https://www.nginx.com/resources/wiki/extending/compiling/), for example:

```
./auto/configure \
        --prefix=/usr \
        --with-stream \
        --with-stream_ssl_module \
        --with-compat \
        --add-dynamic-module=/path/to/src/of/nginx-rpc-tls-module
```

## How to use

Run nginx as you normally might, following the basic pattern in the provided [example configuration](example_nginx.conf).
