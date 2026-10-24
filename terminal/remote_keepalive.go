package terminal

import (
	"errors"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

const (
	remoteOutputQueueSize  = 32
	remotePongWriteTimeout = 5 * time.Second
)

func attachRemotePingHandler(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	conn.SetPingHandler(func(appData string) error {
		err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(remotePongWriteTimeout))
		return ignoreRemoteKeepaliveWriteError(err)
	})
}

func ignoreRemoteKeepaliveWriteError(err error) error {
	if err == nil || errors.Is(err, websocket.ErrCloseSent) {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return nil
	}
	return err
}

func enqueueRemoteOutput(output chan []byte, chunk []byte, done <-chan struct{}) bool {
	if len(chunk) == 0 {
		return true
	}
	select {
	case <-done:
		return false
	case output <- chunk:
		return true
	default:
	}
	select {
	case <-done:
		return false
	case <-output:
	default:
	}
	select {
	case <-done:
		return false
	case output <- chunk:
		return true
	default:
		return true
	}
}
