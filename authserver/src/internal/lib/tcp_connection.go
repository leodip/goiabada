package lib

import (
	"net"
	"strconv"
	"time"
)

func TestTCPConnection(host string, port int) error {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return err
	}
	if conn != nil {
		defer conn.Close()
	}
	return nil
}
