package coreadapter

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	c    *websocket.Conn
	rbuf []byte
}

func newWSConn(c *websocket.Conn) *wsConn {
	return &wsConn{c: c}
}

func (w *wsConn) Read(p []byte) (int, error) {
	for len(w.rbuf) == 0 {
		_, msg, err := w.c.ReadMessage()
		if err != nil {
			return 0, err
		}
		w.rbuf = msg
	}
	n := copy(p, w.rbuf)
	w.rbuf = w.rbuf[n:]
	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.c.WriteMessage(websocket.BinaryMessage, append([]byte(nil), p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error {
	return w.c.Close()
}

func (w *wsConn) LocalAddr() net.Addr {
	return w.c.LocalAddr()
}

func (w *wsConn) RemoteAddr() net.Addr {
	return w.c.RemoteAddr()
}

func (w *wsConn) SetDeadline(t time.Time) error {
	if err := w.c.SetReadDeadline(t); err != nil {
		return err
	}
	return w.c.SetWriteDeadline(t)
}

func (w *wsConn) SetReadDeadline(t time.Time) error {
	return w.c.SetReadDeadline(t)
}

func (w *wsConn) SetWriteDeadline(t time.Time) error {
	return w.c.SetWriteDeadline(t)
}
