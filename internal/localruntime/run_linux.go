//go:build linux

package localruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

func Main(ctx context.Context, args []string, out, diagnostic io.Writer) int {
	if handled, code := nftfixture.HandleRole(args); handled {
		return code
	}
	if e := dispatch(ctx, args, out); e != nil {
		_, _ = io.WriteString(diagnostic, ErrUnavailable.Error()+"\n")
		return 1
	}
	return 0
}
func readPrivate(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	return readFile(filepath.Dir(path), filepath.Base(path), 0, 0, 0600, maxBootstrap)
}
func dispatch(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 3 && args[0] == "--local-services" {
		h, e := strconv.ParseUint(args[1], 10, 64)
		p, pe := strconv.Atoi(args[2])
		if e != nil || pe != nil {
			return ErrUnavailable
		}
		return apiProcess(ctx, h, p, out)
	}
	if len(args) == 4 && args[0] == "--guardian" {
		h, e := strconv.ParseUint(args[2], 10, 64)
		p, pe := strconv.Atoi(args[3])
		if e != nil || pe != nil {
			return ErrUnavailable
		}
		return helperProcess(ctx, args[1], h, p, out)
	}
	if len(args) == 4 && args[0] == "--local-probe" {
		h, e := strconv.ParseUint(args[1], 10, 64)
		p, pe := strconv.Atoi(args[2])
		if e != nil || pe != nil {
			return ErrUnavailable
		}
		return probeProcess(ctx, h, p, args[3], out)
	}
	if os.Geteuid() != 0 {
		return ErrUnavailable
	}
	if len(args) == 3 && args[0] == "provision" {
		b, e := readPrivate(args[2])
		var c Config
		if e != nil || firewallipc.Decode(b, &c) != nil {
			return ErrUnavailable
		}
		if e = provision(args[1], c); e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(map[string]any{"provisioned": true, "directory": args[1]})
	}
	if len(args) == 3 && args[0] == "run" && args[1] == "--snapshot-confirmed" {
		return supervise(ctx, args[2], out)
	}
	if len(args) < 2 {
		return ErrUnavailable
	}
	r := controlRequest{Operation: args[0]}
	switch args[0] {
	case "check", "stop", "reset":
		if len(args) != 2 {
			return ErrUnavailable
		}
	case "fault":
		if len(args) != 3 {
			return ErrUnavailable
		}
		r.Fault = args[2]
	case "probe":
		if len(args) != 4 {
			return ErrUnavailable
		}
		b, e := readPrivate(args[2])
		var p ProbeRequest
		if e != nil || firewallipc.Decode(b, &p) != nil || p.validate() != nil {
			return ErrUnavailable
		}
		r.Probe = &p
	default:
		return ErrUnavailable
	}
	reply, e := controlCall(ctx, args[1], r)
	if e != nil || reply.Error != "" {
		return ErrUnavailable
	}
	if r.Operation == "probe" {
		if reply.Probe == nil {
			return ErrUnavailable
		}
		if e = openExclusiveOutput(args[3], encode(reply.Probe)); e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(map[string]any{"operation": "probe", "output_written": true})
	}
	if reply.Status != nil {
		return json.NewEncoder(out).Encode(reply.Status)
	}
	return json.NewEncoder(out).Encode(map[string]any{"operation": r.Operation, "accepted": true})
}
func controlCall(ctx context.Context, dir string, r controlRequest) (controlReply, error) {
	if _, _, e := load(dir); e != nil {
		return controlReply{}, e
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "control.sock"))
	if e != nil {
		return controlReply{}, e
	}
	defer c.Close()
	if boundedConn(c) != nil {
		return controlReply{}, ErrUnavailable
	}
	u, ok := c.(*net.UnixConn)
	if !ok || !rootPeer(u) {
		return controlReply{}, ErrUnavailable
	}
	if json.NewEncoder(c).Encode(r) != nil {
		return controlReply{}, ErrUnavailable
	}
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), maxBootstrap)
	if !scan.Scan() {
		return controlReply{}, ErrUnavailable
	}
	var reply controlReply
	if firewallipc.Decode(scan.Bytes(), &reply) != nil {
		return controlReply{}, ErrUnavailable
	}
	return reply, nil
}
