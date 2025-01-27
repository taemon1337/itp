package router

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
)

// Router handles connection routing and echo functionality
type Router struct {
	echoMode bool
}

// New creates a new router instance
func New(echoMode bool) *Router {
	return &Router{
		echoMode: echoMode,
	}
}

// HandleEchoConnection handles echo server functionality
func (r *Router) HandleEchoConnection(conn net.Conn, prefix string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		bytes, err := reader.ReadBytes(byte('\n'))
		if err != nil {
			if err != io.EOF {
				fmt.Println("failed to read data, err:", err)
			}
			return
		}
		fmt.Printf("request: %s", bytes)

		line := fmt.Sprintf("%s %s", prefix, bytes)
		fmt.Printf("response: %s", line)
		conn.Write([]byte(line))
	}
}

// IsEchoMode returns whether the router is in echo mode
func (r *Router) IsEchoMode() bool {
	return r.echoMode
}
