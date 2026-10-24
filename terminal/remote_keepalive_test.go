package terminal

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestKeepaliveWriteTimeoutDoesNotFailTheReadLoop(t *testing.T) {
	if err := ignoreRemoteKeepaliveWriteError(nil); err != nil {
		t.Fatalf("nil keepalive error = %v", err)
	}
	if err := ignoreRemoteKeepaliveWriteError(websocket.ErrCloseSent); err != nil {
		t.Fatalf("close-sent keepalive error = %v", err)
	}
	if err := ignoreRemoteKeepaliveWriteError(timeoutError{}); err != nil {
		t.Fatalf("timeout keepalive error = %v", err)
	}
	if err := ignoreRemoteKeepaliveWriteError(errors.New("connection reset")); err == nil {
		t.Fatal("a real connection error was swallowed")
	}
	var netErr net.Error = timeoutError{}
	if !netErr.Timeout() {
		t.Fatal("test timeout error must implement net.Error")
	}
}

func TestRemoteOutputQueueDropsOldestWhenTheWriterIsBlocked(t *testing.T) {
	done := make(chan struct{})
	output := make(chan []byte, 2)
	output <- []byte("old-1")
	output <- []byte("old-2")

	if !enqueueRemoteOutput(output, []byte("new"), done) {
		t.Fatal("enqueue reported that the session had ended")
	}
	first := <-output
	second := <-output
	if string(first) != "old-2" || string(second) != "new" {
		t.Fatalf("queued output = %q %q, want oldest dropped", first, second)
	}
	if !enqueueRemoteOutput(output, nil, done) {
		t.Fatal("empty chunk ended the session")
	}
}

func TestRemoteOutputQueueStopsAfterTheSessionEnds(t *testing.T) {
	done := make(chan struct{})
	close(done)
	output := make(chan []byte)
	if enqueueRemoteOutput(output, []byte("late"), done) {
		t.Fatal("enqueue kept accepting output after the session ended")
	}
}

func TestRemotePongWriteTimeoutStaysBelowIdleSessionLimits(t *testing.T) {
	if remotePongWriteTimeout != 5*time.Second {
		t.Fatalf("pong write timeout = %s, want 5s", remotePongWriteTimeout)
	}
	if remoteOutputQueueSize < 8 {
		t.Fatalf("output queue size = %d, want room for a short burst", remoteOutputQueueSize)
	}
}
