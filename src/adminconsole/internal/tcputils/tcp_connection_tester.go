package tcputils

import (
	"net"
	"strconv"
	"time"
)

type TCPConnectionTester struct {
	timeout time.Duration
}

func NewTCPConnectionTester(timeout time.Duration) *TCPConnectionTester {
	return &TCPConnectionTester{
		timeout: timeout,
	}
}

func (tct *TCPConnectionTester) TestTCPConnection(host string, port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), tct.timeout)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}
	return nil
}
