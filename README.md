# bpf-go-socket-filter

The `socket-filter` program demonstrates how to load an eBPF program from an ELF file,
and attach it to a raw socket.

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
git clone --recurse-submodules https://github.com/danielpacak/bpf-go-socket-filter.git
```
or
```
git clone https://github.com/danielpacak/bpf-go-socket-filter.git
cd bpf-go-socket-filter
git submodule update --init --recursive
```

Compile BPF application and Go loader:

```
make
```

Run the application:

``` console
$ sudo ./socket-filter --index=0
Filtering on eth index: 0
        ICMP: 20 TCP: 121 UDP: 12_
```
