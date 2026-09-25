package wgconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePeers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "office.conf")
	contents := `[Interface]
PrivateKey = secret

[Peer]
PublicKey = firstkey=
Endpoint = vpn.example.net:51820

[Peer]
PublicKey = secondkey=
Endpoint = [2001:db8::1]:51821 # comment
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	peers, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("got %d peers", len(peers))
	}
	if peers[0].Host != "vpn.example.net" || peers[0].Port != 51820 {
		t.Fatalf("unexpected first peer: %#v", peers[0])
	}
	if peers[1].Host != "2001:db8::1" || peers[1].Port != 51821 {
		t.Fatalf("unexpected second peer: %#v", peers[1])
	}
}

func TestParseRejectsEndpointWithoutKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.conf")
	if err := os.WriteFile(path, []byte("[Peer]\nEndpoint=x.example:1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(path); err == nil {
		t.Fatal("expected error")
	}
}
