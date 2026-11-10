//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

type healthRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
}
type HealthResult struct {
	Available bool `json:"available"`
}

func startHealth(ctx context.Context, ids Identities, client *firewallipc.Client) (func(), error) {
	l, e := listenPrivate(HealthSocket, ids.APIUID, ids.APIGID)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(HealthSocket)
	if e != nil {
		l.Close()
		return nil, ErrStorage
	}
	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { l.Close(); <-done; removeSocket(HealthSocket, st) }) }
	go func() {
		defer close(done)
		for {
			c, e := l.AcceptUnix()
			if e != nil {
				return
			}
			if peer(c, 0, 0) != nil && peer(c, ids.APIUID, ids.APIGID) != nil {
				c.Close()
				continue
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReaderSize(c, 4096)
			b, e := r.ReadSlice('\n')
			var request healthRequest
			if e == nil && firewallipc.Decode(b, &request) == nil && request == (healthRequest{Version: 1, Operation: "health"}) {
				call, cancel := context.WithTimeout(ctx, 2*time.Second)
				state, e := client.State(call)
				cancel()
				available := e == nil && state.Phase != "blocked" && state.Phase != "bootstrap"
				_ = json.NewEncoder(c).Encode(HealthResult{Available: available})
			}
			c.Close()
		}
	}()
	return stop, nil
}
func Health(ctx context.Context, c Config) (HealthResult, error) {
	ids, e := LoadIdentities(c)
	if e != nil {
		return HealthResult{}, e
	}
	if socketInfo(HealthSocket, ids.APIUID, ids.APIGID) != nil {
		return HealthResult{}, ErrIdentity
	}
	dial := net.Dialer{Timeout: 3 * time.Second}
	conn, e := dial.DialContext(ctx, "unix", HealthSocket)
	if e != nil {
		return HealthResult{}, ErrUnavailable
	}
	socket := conn.(*net.UnixConn)
	defer socket.Close()
	if peer(socket, ids.APIUID, ids.APIGID) != nil {
		return HealthResult{}, ErrIdentity
	}
	_ = socket.SetDeadline(time.Now().Add(3 * time.Second))
	if json.NewEncoder(socket).Encode(healthRequest{Version: 1, Operation: "health"}) != nil {
		return HealthResult{}, ErrUnavailable
	}
	b, e := bufio.NewReaderSize(socket, 4096).ReadSlice('\n')
	var result HealthResult
	if e != nil || firewallipc.Decode(b, &result) != nil {
		return HealthResult{}, ErrUnavailable
	}
	if !result.Available {
		return result, ErrUnavailable
	}
	return result, nil
}
