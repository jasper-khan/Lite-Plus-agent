package terminal

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
)

type remoteWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (writer *remoteWriter) writeMessage(messageType int, data []byte) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.conn.WriteMessage(messageType, data)
}

func (writer *remoteWriter) writeJSON(value any) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.conn.WriteJSON(value)
}

func (writer *remoteWriter) writeBinary(data []byte) error {
	return writer.writeMessage(websocket.BinaryMessage, data)
}

func StartRemoteSession(conn *websocket.Conn) {
	writer := &remoteWriter{conn: conn}
	attachRemotePingHandler(conn)
	if !remoteControlEnabled() {
		_ = writer.writeJSON(map[string]any{"type": "remote.error", "message": "Remote control is disabled on this agent"})
		return
	}
	impl, err := newTerminalImpl()
	if err != nil {
		_ = writer.writeJSON(map[string]any{"type": "remote.error", "message": fmt.Sprintf("Failed to start terminal: %v", err)})
		return
	}
	manager := newFileManager(writer)
	done := make(chan struct{})
	errCh := make(chan error, 2)
	output := make(chan []byte, remoteOutputQueueSize)
	defer func() {
		close(done)
		manager.close()
		gracefulShutdown(impl.term)
		_ = impl.term.Close()
	}()

	_ = writer.writeJSON(map[string]any{
		"type":          "remote.ready",
		"roots":         filesystemRoots(),
		"home":          userHomeDirectory(),
		"separator":     pathSeparator(),
		"file_transfer": fileTransferVersion,
	})

	go handleRemoteTerminalOutput(impl.term, output, errCh, done)
	go writeRemoteTerminalOutput(writer, output, errCh, done)
	go func() {
		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			switch messageType {
			case websocket.BinaryMessage:
				if manager.enqueueFileFrame(payload) {
					continue
				}
				if _, err := impl.term.Write(payload); err != nil {
					errCh <- err
					return
				}
			case websocket.TextMessage:
				var command struct {
					Type string `json:"type"`
					Cols int    `json:"cols,omitempty"`
					Rows int    `json:"rows,omitempty"`
				}
				if err := json.Unmarshal(payload, &command); err != nil {
					continue
				}
				switch command.Type {
				case "resize":
					if command.Cols > 0 && command.Rows > 0 {
						_ = impl.term.Resize(command.Cols, command.Rows)
					}
				case "heartbeat":
					_ = writer.writeJSON(map[string]any{"type": "heartbeat"})
				default:
					if isFileMessage(command.Type) {
						manager.enqueue(payload)
					}
				}
			}
		}
	}()
	for {
		select {
		case <-errCh:
			return
		}
	}
}

func handleRemoteTerminalOutput(term Terminal, output chan []byte, errCh chan<- error, done <-chan struct{}) {
	buffer := make([]byte, 4096)
	for {
		select {
		case <-done:
			return
		default:
		}
		count, err := term.Read(buffer)
		if err != nil {
			signalRemoteError(errCh, err)
			return
		}
		if count == 0 {
			continue
		}
		if !enqueueRemoteOutput(output, append([]byte(nil), buffer[:count]...), done) {
			return
		}
	}
}

func writeRemoteTerminalOutput(writer *remoteWriter, output <-chan []byte, errCh chan<- error, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case chunk, ok := <-output:
			if !ok {
				return
			}
			if err := writer.writeMessage(websocket.BinaryMessage, chunk); err != nil {
				signalRemoteError(errCh, err)
				return
			}
		}
	}
}

func signalRemoteError(errCh chan<- error, err error) {
	select {
	case errCh <- err:
	default:
	}
}
