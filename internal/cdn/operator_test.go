package cdn

import "testing"

func TestEveryGeoSteeringRootHasExactlyOneOperator(t *testing.T) {
	owners := make(map[string]string)
	for _, op := range operators {
		for _, root := range op.Roots {
			if prev, dup := owners[root]; dup {
				t.Errorf("%s 同时属于 %s 和 %s——归属必须唯一，否则规则集里同一段会打两个 provider", root, prev, op.ID)
			}
			owners[root] = op.ID
		}
	}
	for _, root := range GeoSteeringRoots() {
		id, ok := OperatorFor(root)
		if !ok {
			t.Errorf("%s 是 geo-steering 根域却查不到 operator", root)
			continue
		}
		if id != owners[root] {
			t.Errorf("%s 的 operator 是 %s，后缀查找给出 %s", root, owners[root], id)
		}
	}
}

func TestOperatorIDsAreUniqueAndNamed(t *testing.T) {
	seen := make(map[string]struct{})
	for _, op := range operators {
		if op.ID == "" || op.Name == "" {
			t.Errorf("operator %+v 缺 ID 或名称", op)
		}
		if _, dup := seen[op.ID]; dup {
			t.Errorf("operator ID %q 重复", op.ID)
		}
		seen[op.ID] = struct{}{}
		if len(op.Roots) == 0 {
			t.Errorf("operator %s 没有任何根域", op.ID)
		}
	}
}

func TestOperatorASNsDoNotCollide(t *testing.T) {
	owner := make(map[int]string)
	for _, op := range operators {
		for _, asn := range op.ASNs {
			if prev, dup := owner[asn]; dup {
				t.Errorf("AS%d 同时挂在 %s 和 %s 下——拉前缀时会把同一批网段算给两家", asn, prev, op.ID)
			}
			owner[asn] = op.ID
		}
	}
	for asn := range dnsOnlyAS {
		if id, dup := owner[asn]; dup {
			t.Errorf("AS%d 既在 dnsOnlyAS 又在 operator %s 下", asn, id)
		}
	}
}

func TestOperatorLookupIsSuffixSafe(t *testing.T) {
	for name, want := range map[string]string{
		"a13-65.akam.net":                   "akamai",
		"www.microsoft.com-c-3.edgekey.net": "akamai",
		"ns1-206.azure-dns.com":             "microsoft",
		"img.alicdn.com":                    "alibaba",
		"foo.cdntip.com":                    "tencent",
	} {
		if id, ok := OperatorFor(name); !ok || id != want {
			t.Errorf("%s 应归属 %s，得到 %q/%v", name, want, id, ok)
		}
	}
	for _, name := range []string{"notakam.net", "akam.net.evil.com", "qq.com", "com"} {
		if id, ok := OperatorFor(name); ok {
			t.Errorf("%s 不该命中任何 operator，却得到 %s", name, id)
		}
	}
}

func TestSharedDNSProviderStillCoversDNSOnlyVendors(t *testing.T) {
	for asn, want := range map[int]string{
		26496: "GoDaddy", 33517: "Dyn", 30060: "Verisign",
		20940: "Akamai", 13335: "Cloudflare", 54113: "Fastly",
		16509: "AWS", 8068: "Microsoft", 19551: "Imperva",
	} {
		if label, ok := SharedDNSProvider(asn); !ok || label != want {
			t.Errorf("AS%d 应识别为 %s，得到 %q/%v", asn, want, label, ok)
		}
	}
}
