# bpf-go-socket

The `socket-filter` program demonstrates how to load an eBPF program from an
ELF file, and attach it to a raw socket.

`BPF_PROG_TYPE_SOCKET_FILTER` was the first program type to be added to the
Linux kernel. When you attach a BPF program to a raw socket, you get access to
all the packets processed by that socket. Socket filter programs don't allow
you to modify the contents of those packets or to change the destination for
those packets; they give you access to them for observability purposes only.
The metadata that your program receives contains information related to the
network stack such as the protocol type that's being used to deliver the
packet.

## Usage

Clone and change current directory to the cloned repository:

```
git clone --recurse-submodules https://github.com/danielpacak/bpf-go-socket.git
```
or
```
git clone https://github.com/danielpacak/bpf-go-socket.git
cd bpf-go-socket
git submodule update --init --recursive
```

Compile BPF application and Go loader:

```
make
```

Run the application as root with `sudo`:

``` console
$ sudo ./socket --index=0
Filtering as uid=0(root) on eth index: 0
        ICMP: 20 TCP: 121 UDP: 12_
```

Run the application as non-root user:

```
sudo setcap 'cap_net_raw=ep cap_bpf=ep' ./socket
```
``` console
$ ./socket
Filtering as uid=1000(dpacak) on eth index: 0
	ICMP: 0 TCP: 6167 UDP: 0_
```

## References

1. [struct __sk_buff](https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/bpf.h#L5913)
2. [struct iphdr](https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/ip.h#L87)
3. [man bpf-helpers(7) - list of eBPF helper functions](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
4. [man capabilities(7) - overview of Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
5. [man raw(7 - Linux IPv4 raw sockets)](https://man7.org/linux/man-pages/man7/raw.7.html)
6. [IPPROTO_TCP - Transmission Control Protocol](https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/in.h#L38)
7. [IPPROTO_UDP - User Datagram Protocol](https://elixir.bootlin.com/linux/v6.2/source/include/uapi/linux/in.h#L44)
