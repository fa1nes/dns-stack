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
		for _, asn := range op.AllASNs() {
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

func TestPrefixASNsStayOutOfTheSharedDNSJudgement(t *testing.T) {
	seen := 0
	for _, op := range operators {
		for _, asn := range op.PrefixASNs {
			seen++
			if label, shared := SharedDNSProvider(asn); shared {
				t.Errorf("AS%d 只是用来拉 %s 的节点前缀，却被当成共享 DNS 提供商(%s)。"+
					"这两个字段回答的不是同一个问题：前者问「这些地址是谁的节点」，"+
					"后者问「这个 ASN 上的权威是不是多租户共享、因而不得直连」", asn, op.ID, label)
			}
		}
	}
	if seen == 0 {
		t.Fatal("一个 PrefixASN 都没有，这条判据本身失效了")
	}
}

func TestPrefixASNsActuallyReachThePrefixBuilder(t *testing.T) {
	for _, op := range Operators() {
		if len(op.PrefixASNs) == 0 {
			continue
		}
		all := op.AllASNs()
		for _, asn := range op.PrefixASNs {
			found := false
			for _, item := range all {
				if item == asn {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s 的 AS%d 没进 AllASNs()，拉前缀那一步永远看不到它——"+
					"填了却拉不到，是最难发现的一种失效", op.ID, asn)
			}
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
