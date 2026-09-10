package panel

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestValidClientSubnet(t *testing.T) {
	for _, value := range []string{"1.2.3.0/24", "8.8.8.0/24"} {
		if !validClientSubnet(value) {
			t.Fatalf("expected valid subnet: %s", value)
		}
	}
	for _, value := range []string{"1.2.3.4/24", "10.0.0.0/24", "2001:db8::/32", "1.2.3.0/32", "1.2.3.0/33", "1.2.3/24"} {
		if validClientSubnet(value) {
			t.Fatalf("expected invalid subnet: %s", value)
		}
	}
}

func TestCompareDNSViews(t *testing.T) {
	view := func(values ...string) map[string]any {
		records := make([]map[string]any, 0, len(values))
		for _, value := range values {
			records = append(records, map[string]any{"type": "A", "value": value})
		}
		return map[string]any{"records": records}
	}
	if got := compareDNSViews(map[string]any{
		"local-unbound": view("1.2.3.4"),
		"foreign-hk":    view("1.2.3.4"),
	}); got != "consistent" {
		t.Fatalf("same views: %s", got)
	}
	if got := compareDNSViews(map[string]any{
		"local-unbound": view("1.2.3.4"),
		"foreign-hk":    view("8.8.8.8"),
	}); got != "geo_split" {
		t.Fatalf("split views: %s", got)
	}
	if got := compareDNSViews(map[string]any{
		"local-unbound": view("127.0.0.1"),
		"foreign-hk":    view("8.8.8.8"),
	}); got != "no_final_global_address" {
		t.Fatalf("non-global answer: %s", got)
	}
}

func TestParseDigECSAndGlobalAddressFilter(t *testing.T) {
	parsed := parseDig(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\nexample.test. 60 IN A 192.0.2.1\nexample.test. 60 IN A 1.2.3.4\n; CLIENT-SUBNET: 1.2.3.0/24/24\n;; Query time: 3 msec")
	if parsed["ecs"] == nil {
		t.Fatal("expected ECS echo")
	}
	if len(parsed["records"].([]map[string]any)) != 1 {
		t.Fatal("expected non-global A to be filtered")
	}
	if len(parsedGlobalIPs(parsed)) != 1 || parsedGlobalIPs(parsed)[0] != "1.2.3.4" {
		t.Fatal("unexpected global address result")
	}
}

func TestDNSInputRejectsLiteralsAndMalformedNames(t *testing.T) {
	for _, name := range []string{"", "1.2.3.4", "2001:db8::1", "example..com", ".example.com", "com"} {
		if validDNSName(name) {
			t.Fatalf("invalid DNS name accepted: %q", name)
		}
	}
	for _, name := range []string{"example.com", "_acme-challenge.example.com"} {
		if !validDNSName(name) {
			t.Fatalf("valid DNS name rejected: %q", name)
		}
	}
}

func TestValidClientSubnetRejectsReservedNetwork(t *testing.T) {
	for _, subnet := range []string{"192.0.2.0/24", "100.64.0.0/24", "1.2.3.4/24"} {
		if validClientSubnet(subnet) {
			t.Fatalf("invalid ECS subnet accepted: %s", subnet)
		}
	}
}

func TestHelperCallUsesContextDeadlineAndSocketOverride(t *testing.T) {
	listener, path := listenTestHelper(t)
	defer listener.Close()
	old := os.Getenv("DNS_STACK_HELPER_SOCK")
	if err := os.Setenv("DNS_STACK_HELPER_SOCK", path); err != nil {
		t.Fatal(err)
	}
	defer os.Setenv("DNS_STACK_HELPER_SOCK", old)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var request map[string]any
		_ = json.NewDecoder(conn).Decode(&request)
		time.Sleep(500 * time.Millisecond)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := helperCall(ctx, "healthcheck", nil); err == nil {
		t.Fatal("helper call ignored context deadline")
	}
}
