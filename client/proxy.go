package main

import (
	"io"
	"log"
	"net"
	"sync"
)

// proxyStream connects an incoming tunnel stream to the local target
// and copies data bidirectionally until either side closes.
func proxyStream(stream net.Conn, streamID int64, targetAddr string) {
	defer stream.Close()

	log.Printf("[%d] New stream, connecting to %s...", streamID, targetAddr)

	// Connect to local target
	targetConn, err := net.DialTimeout("tcp", targetAddr, ProxyTimeout)
	if err != nil {
		log.Printf("[%d] Failed to connect to target: %v", streamID, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[%d] Connected to target, proxying...", streamID)

	// Bidirectional copy between tunnel stream and target
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> Target
	go func() {
		defer wg.Done()
		io.Copy(targetConn, stream)
		targetConn.Close()
	}()

	// Target -> Stream
	go func() {
		defer wg.Done()
		io.Copy(stream, targetConn)
		stream.Close()
	}()

	wg.Wait()
	log.Printf("[%d] Stream closed", streamID)
}
