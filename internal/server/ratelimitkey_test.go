package server

import (
	"net/netip"
	"testing"
)

// Covers: SEC-24 (part)
func TestRateKey(t *testing.T) {
	tests := []struct {
		name string
		in   netip.Addr
		want netip.Addr
	}{
		{"IPv4 address is its own key", netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")},
		{"IPv4 address at the bottom of the range", netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("0.0.0.0")},
		{"IPv4-mapped IPv6 address is its IPv4 address", netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("192.0.2.1")},
		{"IPv6 host is its /64 prefix", netip.MustParseAddr("2001:db8:1:2::1f"), netip.MustParseAddr("2001:db8:1:2::")},
		{"last address of a /64 is in that /64", netip.MustParseAddr("2001:db8:0:0:ffff:ffff:ffff:ffff"), netip.MustParseAddr("2001:db8::")},
		{"first address of the next /64 is another key", netip.MustParseAddr("2001:db8:0:1::"), netip.MustParseAddr("2001:db8:0:1::")},
		{"the loopback address is the /64 of ::", netip.MustParseAddr("::1"), netip.MustParseAddr("::")},
		{"zone is dropped", netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("fe80::")},
		{"zero address stays zero", netip.Addr{}, netip.Addr{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rateKey(tt.in); got != tt.want {
				t.Errorf("rateKey(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
