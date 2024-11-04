package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
)

type HostDetails struct {
	Hostname    string
	PacketCount int
	ByteCount   int
}

type HostMap struct {
	sync.RWMutex
	data map[string]*HostDetails
}

func (hm *HostMap) Add(host string) bool {
	hm.Lock()
	defer hm.Unlock()

	if _, exists := hm.data[host]; !exists {
		hostname, err := net.LookupAddr(host)
		if err != nil || len(hostname) == 0 {
			hostname = []string{"Unknown"}
		}
		hm.data[host] = &HostDetails{
			Hostname:    hostname[0],
			PacketCount: 0,
			ByteCount:   0,
		}
		return true
	}
	return false
}

func (hm *HostMap) UpdateHostMetrics(host string, packetLen int) {
	hm.Lock()
	defer hm.Unlock()

	if details, exists := hm.data[host]; exists {
		details.PacketCount++
		details.ByteCount += packetLen
	}
}

func listHosts(itfaddr string, hostMap *HostMap) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Print("\033[H\033[2J")
			fmt.Println("Connected hosts:")
			hostMap.RLock()
			for ip, details := range hostMap.data {
				if ip == itfaddr {
					fmt.Print("↪")
				}
				fmt.Printf(" Host: %s, Hostname: %s, Packets: %d, Bytes: %d\n", ip, details.Hostname, details.PacketCount, details.ByteCount)
			}
			hostMap.RUnlock()
		}
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("error loading .env file")
	}

	itf := os.Getenv("ITF")
	ip, subnet, err := getInterface(itf)
	if err != nil {
		log.Fatalf("failed to get IP address for interface %s: %v", itf, err)
	}

	deployment, err := runMake("deploy", fmt.Sprintf("ITF=%s", itf))
	if err != nil {
		log.Fatalf("failed running `deploy` target: %v", err)
	}
	capture, err := runMake("capture")
	if err != nil {
		log.Fatalf("failed running `capture` target: %v", err)
	}
	defer func() {
		if err := stopProc(deployment); err != nil {
			log.Fatalf("failted to stop `deployment target`: %v", err)
		}
		if err := stopProc(capture); err != nil {
			log.Fatalf("failed to stop `capture` target: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if _, err := runMake("destroy"); err != nil {
			log.Fatalf("failed running `destroy` target: %v", err)
		}
		if _, err := runMake("clean"); err != nil {
			log.Fatalf("failed running `clean` target: %v", err)
		}
		os.Exit(0)
	}()

	hostMap := &HostMap{data: make(map[string]*HostDetails)}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitor(itf, subnet, hostMap)
	}()
	go listHosts(ip, hostMap)
	wg.Wait()
}

func monitor(itf string, subnet *net.IPNet, hostMap *HostMap) {
	handle, err := pcap.OpenLive(itf, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		process(packet, subnet, hostMap)
	}
}

func process(packet gopacket.Packet, subnet *net.IPNet, hostMap *HostMap) {
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	src, dst := networkLayer.NetworkFlow().Endpoints()
	srcIP, dstIP := src.String(), dst.String()

	packetLength := len(packet.Data())
	if subnet.Contains(net.ParseIP(srcIP)) && hostMap.Add(srcIP) {
		// go scan(srcIP, subnet)
	}
	if subnet.Contains(net.ParseIP(dstIP)) && hostMap.Add(dstIP) {
		// go scan(dstIP, subnet)
	}

	if subnet.Contains(net.ParseIP(srcIP)) {
		hostMap.UpdateHostMetrics(srcIP, packetLength)
	}
	if subnet.Contains(net.ParseIP(dstIP)) {
		hostMap.UpdateHostMetrics(dstIP, packetLength)
	}
}

func getInterface(interfaceName string) (string, *net.IPNet, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", nil, err
	}

	for _, addr := range addrs {
		var ip net.IP
		var ipnet *net.IPNet
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
			ipnet = v
		case *net.IPAddr:
			ip = v.IP
			ipnet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		return ip.String(), ipnet, nil
	}
	return "", nil, fmt.Errorf("no valid IP address found for interface %s", interfaceName)
}

func runMake(target string, args ...string) (*exec.Cmd, error) {
	args = append(args, target)
	cmd := exec.Command("make", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed running target %s: %v", target, err)
	}
	return cmd, nil
}

func stopProc(cmd *exec.Cmd) error {
	if cmd != nil && cmd.Process != nil {
		return cmd.Process.Signal(syscall.SIGINT)
	}
	return nil
}
