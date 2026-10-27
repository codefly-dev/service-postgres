package main

// forward.go — a service's own endpoint on its run's shared server.
//
// The run's server listens on a private Unix socket only (nixpg.go). Each
// service keeps the TCP endpoint Codefly allocated it: its agent listens there,
// on loopback as the per-service server did, and carries every connection to
// the socket byte for byte. Authentication (SCRAM) is between the client and
// the server, so the agent sees no credential, and the address in every
// connection string a consumer receives is the one it always was.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type socketForwarder struct {
	listener net.Listener
	socket   string

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// forwardToSocket listens on address and forwards each connection to socket.
func forwardToSocket(address, socket string) (*socketForwarder, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on this service's endpoint %s: %w", address, err)
	}
	f := &socketForwarder{listener: listener, socket: socket, conns: map[net.Conn]struct{}{}}
	f.wg.Add(1)
	go f.serve()
	return f, nil
}

func (f *socketForwarder) serve() {
	defer f.wg.Done()
	for {
		client, err := f.listener.Accept()
		if err != nil {
			return
		}
		if !f.track(client) {
			_ = client.Close()
			return
		}
		f.wg.Add(1)
		go f.pipe(client)
	}
}

func (f *socketForwarder) pipe(client net.Conn) {
	defer f.wg.Done()
	defer f.untrack(client)
	server, err := net.DialTimeout("unix", f.socket, 5*time.Second)
	if err != nil {
		return
	}
	if !f.track(server) {
		_ = server.Close()
		return
	}
	defer f.untrack(server)
	done := make(chan struct{}, 2)
	carry := func(to, from net.Conn) {
		_, _ = io.Copy(to, from)
		done <- struct{}{}
	}
	go carry(server, client)
	go carry(client, server)
	// Either side ending ends the session: closing both unblocks the other copy.
	<-done
	_ = client.Close()
	_ = server.Close()
	<-done
}

func (f *socketForwarder) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[conn] = struct{}{}
	return true
}

func (f *socketForwarder) untrack(conn net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.conns, conn)
	_ = conn.Close()
}

// Close stops listening and ends every forwarded session, so the endpoint is
// released the moment the service is.
func (f *socketForwarder) Close() error {
	f.mu.Lock()
	f.closed = true
	err := f.listener.Close()
	for conn := range f.conns {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
