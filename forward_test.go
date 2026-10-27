package main

import (
	"bufio"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestForwarderCarriesSessionsToTheSocketAndReleasesThePort is the forwarder's
// whole contract: bytes both ways, unchanged, and nothing left listening or
// connected once the service is released.
func TestForwarderCarriesSessionsToTheSocketAndReleasesThePort(t *testing.T) {
	socket := filepath.Join(shortTempDir(t), "s")
	upstream, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					_, _ = conn.Write([]byte("echo " + line))
				}
				// Hold the session open, as a database connection does.
				_, _ = conn.Read(make([]byte, 1))
			}(conn)
		}
	}()

	forwarder, err := forwardToSocket("127.0.0.1:0", socket)
	require.NoError(t, err)
	address := forwarder.listener.Addr().String()

	client, err := net.DialTimeout("tcp", address, time.Second)
	require.NoError(t, err)
	_, err = client.Write([]byte("hello\n"))
	require.NoError(t, err)
	reply, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "echo hello\n", reply)

	require.NoError(t, forwarder.Close())
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err, "a released endpoint must end the sessions it carried")
	_, err = net.DialTimeout("tcp", address, time.Second)
	require.Error(t, err, "a released endpoint must stop listening")
}

func TestForwarderRefusesAnEndpointAlreadyInUse(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer taken.Close()
	_, err = forwardToSocket(taken.Addr().String(), filepath.Join(t.TempDir(), "s"))
	require.ErrorContains(t, err, "listen on this service's endpoint")
}
