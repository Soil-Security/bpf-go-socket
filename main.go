package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

const SO_ATTACH_BPF = 50

const (
	ICMP = 0x01
	TCP  = 0x06
	UDP  = 0x11
)

func main() {
	if err := run(setupHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func run(ctx context.Context) error {
	index := flag.Int("index", 0, "specify ethernet index")
	flag.Parse()

	var bpfObjects bpfObjects

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	bpfObjectFile := path.Join(filepath.Dir(executable), "socket.bpf.o")

	spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
	if err != nil {
		return err
	}

	err = spec.LoadAndAssign(&bpfObjects, &ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	defer bpfObjects.Close()

	sock, err := openRawSock(*index)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)

	err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, bpfObjects.SocketProg.FD())
	if err != nil {
		return err
	}

	fmt.Printf("Filtering as uid=%d(%s) on eth index: %d\n", os.Getuid(), os.Getenv("USER"), *index)

	go func() {
		for {
			time.Sleep(time.Second)

			var icmp uint32
			var tcp uint32
			var udp uint32
			err := bpfObjects.CountMap.Lookup(uint32(ICMP), &icmp)
			if err != nil {
				panic(err)
			}
			err = bpfObjects.CountMap.Lookup(uint32(TCP), &tcp)
			if err != nil {
				panic(err)
			}
			err = bpfObjects.CountMap.Lookup(uint32(UDP), &udp)
			if err != nil {
				panic(err)
			}
			fmt.Printf("\r\033[m\tICMP: %d TCP: %d UDP: %d", icmp, tcp, udp)
		}
	}()

	<-ctx.Done()

	return nil
}

var onlyOneSignalHandler = make(chan struct{})

func setupHandler() context.Context {
	close(onlyOneSignalHandler)

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfPrograms struct {
	SocketProg *ebpf.Program `ebpf:"socket_prog"`
}

func (p *bpfPrograms) Close() error {
	return bpfClose(
		p.SocketProg,
	)
}

type bpfMaps struct {
	CountMap *ebpf.Map `ebpf:"countmap"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.CountMap,
	)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	err = syscall.Bind(sock, &sll)
	if err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
