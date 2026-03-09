package main

import (
	"io"
	"log"
	"net"
	"sync"
)

// proxyStream connects an incoming tunnel stream to the local target
// and copies data bidirectionally until either side closes.
func proxyStream(stream net.Conn, targetAddr string) {
	defer stream.Close()

	// Connect to local target
	targetConn, err := net.DialTimeout("tcp", targetAddr, ProxyTimeout)
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy between tunnel stream and target
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, stream)
		targetConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, targetConn)
		stream.Close()
	}()

	wg.Wait()
}
