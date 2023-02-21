# bpf-raw-socket-filter

The `socket-filter` program demonstrates how to load an eBPF program from an ELF file,
and attach it to a raw socket.

## Usage

Clone and change current directory to the cloned repository:

```
git clone https://github.com/danielpacak/bpf-raw-socket-filter.git
cd bpf-raw-socket-filter
git submodule update --init --recursive
```

Compile BPF application and Go loader:

```
make -C src all
```

Run the application:

``` console
$ sudo ./src/socket-filter --index=0
Filtering on eth index: 0
        ICMP: 20 TCP: 121 UDP: 12_
```
