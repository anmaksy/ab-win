//go:build windows

// Package ipc is newline-delimited JSON-RPC over named pipes between the
// service and the CLI/tray.
//
// Two pipes keep the lock_settings rule enforceable by Windows itself:
//   - \\.\pipe\ab-win-status: read-only methods; any interactive user.
//   - \\.\pipe\ab-win:        every method; interactive users too unless
//     lock_settings is on, in which case only SYSTEM and Administrators.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	PipeControl = `\\.\pipe\ab-win`
	PipeStatus  = `\\.\pipe\ab-win-status`
)

// ReadOnly lists methods served on the status pipe.
var ReadOnly = map[string]bool{
	"status": true, "why": true, "recent": true, "lists": true, "recent_blocked": true, "version": true,
}

const (
	sddlOpen   = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)(A;;GRGW;;;S-1-5-32-545)"
	sddlLocked = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

type request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler serves one call.
type Handler func(method string, params json.RawMessage) (any, error)

// Server owns both pipe listeners.
type Server struct {
	Handler Handler
	Prefix  string // pipe name override for tests ("" = production names)

	control net.Listener
	status  net.Listener
	locked  bool
}

func (s *Server) names() (control, status string) {
	if s.Prefix != "" {
		return s.Prefix, s.Prefix + "-status"
	}
	return PipeControl, PipeStatus
}

// Start listens on both pipes.
func (s *Server) Start(locked bool) error {
	control, status := s.names()
	st, err := winio.ListenPipe(status, &winio.PipeConfig{SecurityDescriptor: sddlOpen})
	if err != nil {
		return fmt.Errorf("status pipe: %w", err)
	}
	s.status = st
	go s.serve(st, true)
	return s.listenControl(control, locked)
}

func (s *Server) listenControl(name string, locked bool) error {
	sddl := sddlOpen
	if locked {
		sddl = sddlLocked
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		return fmt.Errorf("control pipe: %w", err)
	}
	s.control, s.locked = l, locked
	go s.serve(l, false)
	return nil
}

// SetLocked re-creates the control pipe with the matching ACL.
func (s *Server) SetLocked(locked bool) error {
	if locked == s.locked && s.control != nil {
		return nil
	}
	if s.control != nil {
		s.control.Close()
	}
	control, _ := s.names()
	return s.listenControl(control, locked)
}

func (s *Server) Close() {
	if s.control != nil {
		s.control.Close()
	}
	if s.status != nil {
		s.status.Close()
	}
}

func (s *Server) serve(l net.Listener, readOnly bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handle(c, readOnly)
	}
}

func (s *Server) handle(c net.Conn, readOnly bool) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var req request
	if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
		return
	}
	var resp response
	if readOnly && !ReadOnly[req.Method] {
		resp.Error = "this method needs the control pipe"
	} else if res, err := s.Handler(req.Method, req.Params); err != nil {
		resp.Error = err.Error()
	} else if res != nil {
		resp.Result, _ = json.Marshal(res)
	}
	b, _ := json.Marshal(resp)
	c.Write(append(b, '\n'))
}

// Errors the CLI turns into friendly messages and exit codes.
var (
	ErrNotRunning = errors.New("ab-win service is not running")
	ErrLocked     = errors.New("settings are locked by an administrator")
)

// RemoteError is an error reported by the service.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return e.Msg }

// Client calls the service.
type Client struct {
	Prefix  string
	Timeout time.Duration
}

// Call runs method with params and decodes the result into out (may be nil).
// Read-only methods use the status pipe so they work under lock_settings.
func (c Client) Call(method string, params, out any) error {
	control, status := PipeControl, PipeStatus
	if c.Prefix != "" {
		control, status = c.Prefix, c.Prefix+"-status"
	}
	name := control
	if ReadOnly[method] {
		name = status
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, context.DeadlineExceeded) {
			return ErrNotRunning
		}
		if errors.Is(err, os.ErrPermission) {
			return ErrLocked
		}
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute)) // `update` may download lists
	req := request{Method: method}
	if params != nil {
		req.Params, _ = json.Marshal(params)
	}
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("reading reply: %w", err)
	}
	if resp.Error != "" {
		return &RemoteError{resp.Error}
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}
