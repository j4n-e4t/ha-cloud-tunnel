package main

import (
	"io"
	"log"
	"net"
	"sync"
)

// proxyStream connects an incoming tunnel stream to the local Home Assistant
// instance and copies data bidirectionally until either side closes.
func proxyStream(stream net.Conn, streamID int64) {
	defer stream.Close()

	log.Printf("[%d] New stream, connecting to %s...", streamID, TargetAddr)

	// Connect to local Home Assistant
	haConn, err := net.DialTimeout("tcp", TargetAddr, ProxyTimeout)
	if err != nil {
		log.Printf("[%d] Failed to connect to HA: %v", streamID, err)
		return
	}
	defer haConn.Close()

	log.Printf("[%d] Connected to Home Assistant, proxying...", streamID)

	// Bidirectional copy between tunnel stream and Home Assistant
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> Home Assistant
	go func() {
		defer wg.Done()
		io.Copy(haConn, stream)
		haConn.Close()
	}()

	// Home Assistant -> Stream
	go func() {
		defer wg.Done()
		io.Copy(stream, haConn)
		stream.Close()
	}()

	wg.Wait()
	log.Printf("[%d] Stream closed", streamID)
}
