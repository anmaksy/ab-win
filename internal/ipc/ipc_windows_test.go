//go:build windows

package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	prefix := fmt.Sprintf(`\\.\pipe\ab-win-test-%d`, time.Now().UnixNano())
	s := &Server{Prefix: prefix, Handler: func(method string, params json.RawMessage) (any, error) {
		switch method {
		case "status":
			return map[string]string{"state": "on"}, nil
		case "allow":
			var p struct{ Domain string }
			json.Unmarshal(params, &p)
			return map[string]string{"allowed": p.Domain}, nil
		}
		return nil, errors.New("unknown method")
	}}
	if err := s.Start(false); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := Client{Prefix: prefix}

	var st map[string]string
	if err := c.Call("status", nil, &st); err != nil || st["state"] != "on" {
		t.Fatalf("status: %v %v", st, err)
	}
	var al map[string]string
	if err := c.Call("allow", map[string]string{"domain": "x.com"}, &al); err != nil || al["allowed"] != "x.com" {
		t.Fatalf("allow: %v %v", al, err)
	}
	var re *RemoteError
	if err := c.Call("nope", nil, nil); !errors.As(err, &re) {
		t.Fatalf("want RemoteError, got %v", err)
	}
	if err := (Client{Prefix: prefix + "-missing", Timeout: 200 * time.Millisecond}).Call("status", nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
}
