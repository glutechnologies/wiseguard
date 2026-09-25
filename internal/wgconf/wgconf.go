package wgconf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Peer struct {
	PublicKey string
	Endpoint  string
	Host      string
	Port      int
}

func Parse(path string) ([]Peer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open WireGuard profile: %w", err)
	}
	defer f.Close()

	var peers []Peer
	var current *Peer
	s := bufio.NewScanner(f)
	for lineNo := 1; s.Scan(); lineNo++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "peer") {
				peers = append(peers, Peer{})
				current = &peers[len(peers)-1]
			} else {
				current = nil
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = stripInlineComment(strings.TrimSpace(value))
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "publickey":
			current.PublicKey = value
		case "endpoint":
			current.Endpoint = value
			host, port, err := splitEndpoint(value)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid Endpoint: %w", path, lineNo, err)
			}
			current.Host, current.Port = host, port
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read WireGuard profile: %w", err)
	}

	forwarded := peers[:0]
	for i, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		if peer.PublicKey == "" {
			return nil, fmt.Errorf("peer %d has Endpoint but no PublicKey", i+1)
		}
		forwarded = append(forwarded, peer)
	}
	if len(forwarded) == 0 {
		return nil, fmt.Errorf("profile has no peer with an Endpoint")
	}
	return forwarded, nil
}

func splitEndpoint(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("expected host:port: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return host, port, nil
}

func stripInlineComment(value string) string {
	for i, r := range value {
		if (r == '#' || r == ';') && i > 0 && (value[i-1] == ' ' || value[i-1] == '\t') {
			return strings.TrimSpace(value[:i])
		}
	}
	return value
}
