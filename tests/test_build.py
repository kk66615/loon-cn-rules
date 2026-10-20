import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build  # noqa: E402


class ParseTest(unittest.TestCase):
    def test_parse_v2ray(self):
        text = "qq.com\nfull:api.example.cn\ndomain:Taobao.com.\nregexp:^.+\\.x\\.cn$\nkeyword:foo\nbad domain\n# c\n"
        suffixes, exacts = build.parse_v2ray(text)
        self.assertEqual(suffixes, {"qq.com", "taobao.com"})
        self.assertEqual(exacts, {"api.example.cn"})

    def test_parse_v2ray_strips_attributes(self):
        suffixes, _ = build.parse_v2ray("example.cn:@cn\n")
        self.assertEqual(suffixes, {"example.cn"})

    def test_parse_dotlist(self):
        suffixes, exacts = build.parse_dotlist("# NAME: x\n.qq.com\nwww.jd.com\n\n")
        self.assertEqual(suffixes, {"qq.com"})
        self.assertEqual(exacts, {"www.jd.com"})

    def test_parse_custom(self):
        text = "dingtalk.com\nDOMAIN-SUFFIX, alipay.com\nDOMAIN,a.b.cn # note\nDOMAIN-KEYWORD,taobao\nIP-CIDR,1.2.3.4/24,no-resolve\n"
        suffixes, exacts, extra = build.parse_custom(text)
        self.assertEqual(suffixes, {"dingtalk.com", "alipay.com"})
        self.assertEqual(exacts, {"a.b.cn"})
        self.assertEqual(extra, ["DOMAIN-KEYWORD,taobao", "IP-CIDR,1.2.3.0/24,no-resolve"])

    def test_parse_custom_rejects_invalid_lines(self):
        for line in ["DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN-SUFIX,y.com", "DOMAIN-SUFFIX,bad domain",
                     ".example.org", "*.x.com", "IP-CIDR,1.2.3.0/24", "IP-CIDR,2001:250::/30,no-resolve"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                build.parse_custom(line + "\n")

    def test_read_custom_strips_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "direct.list").write_text("\ufeffqq.com\n", encoding="utf-8")
            with mock.patch.object(build, "CUSTOM", Path(tmp)):
                suffixes, _, _ = build.parse_custom(build.read_custom("direct.list"))
        self.assertEqual(suffixes, {"qq.com"})

    def test_parse_cidrs(self):
        nets = build.parse_cidrs("1.0.1.0/24\n2001:250::/30\n")
        self.assertEqual([n.version for n in nets], [4, 6])


class TransformTest(unittest.TestCase):
    def test_compact_removes_covered_entries(self):
        suffixes, exacts = build.compact({"qq.com", "weixin.qq.com", "cn", "example.cn"}, {"www.qq.com", "a.jd.com"})
        self.assertEqual(suffixes, {"qq.com", "cn"})
        self.assertEqual(exacts, {"a.jd.com"})

    def test_compact_does_not_confuse_label_boundaries(self):
        suffixes, _ = build.compact({"qq.com", "myqq.com"}, set())
        self.assertEqual(suffixes, {"qq.com", "myqq.com"})

    def test_apply_excludes_drops_domain_and_children(self):
        suffixes, exacts = build.apply_excludes(
            {"example.com", "a.example.com", "qq.com"}, {"b.example.com", "www.jd.com"}, {"example.com"})
        self.assertEqual(suffixes, {"qq.com"})
        self.assertEqual(exacts, {"www.jd.com"})

    def test_collapse_merges_adjacent_networks(self):
        v4, v6 = build.collapse([ipaddress.ip_network("1.0.0.0/25"), ipaddress.ip_network("1.0.0.128/25"),
                                 ipaddress.ip_network("2001:250::/30")])
        self.assertEqual([str(n) for n in v4], ["1.0.0.0/24"])
        self.assertEqual([str(n) for n in v6], ["2001:250::/30"])

    def test_covering_suffix(self):
        self.assertEqual(build.covering_suffix("weixin.qq.com", {"qq.com"}), "qq.com")
        self.assertIsNone(build.covering_suffix("qq.com", {"qq.com"}, include_self=False))


FIXTURES = {
    "v2ray": "qq.com\ntaobao.com\nalipay.com\ndingtalk.com\njd.com\nfull:www.qq.com\nexample.cn\n",
    "dotlist": ".cn\nwww.jd.com\nonly.example.net\n",
    "cidr": "1.0.1.0/24\n2001:250::/30\n",
}


def fake_fetch(url):
    if url.endswith("direct-list.txt"):
        return FIXTURES["v2ray"]
    if url.endswith("_Domain.list"):
        return FIXTURES["dotlist"]
    return FIXTURES["cidr"]


class BuildTest(unittest.TestCase):
    def run_build(self, direct="", exclude="", min_domains=1):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "custom").mkdir()
        (root / "custom" / "direct.list").write_text(direct, encoding="utf-8")
        (root / "custom" / "exclude.list").write_text(exclude, encoding="utf-8")
        with mock.patch.multiple(build, fetch=fake_fetch, DIST=root / "dist", CUSTOM=root / "custom",
                                 MIN_DOMAINS_PER_SOURCE=min_domains, MIN_CIDRS_PER_SOURCE=1):
            build.build()
        return root / "dist"

    def test_output_format(self):
        dist = self.run_build(direct="DOMAIN-KEYWORD,alicdn\n", exclude="only.example.net\n")
        domain = (dist / "CN_Domain.list").read_text().splitlines()
        rules = [l for l in domain if not l.startswith("#")]
        self.assertEqual(rules[0], "DOMAIN-KEYWORD,alicdn")
        self.assertIn("DOMAIN-SUFFIX,cn", rules)
        self.assertIn("DOMAIN-SUFFIX,qq.com", rules)
        self.assertNotIn("DOMAIN-SUFFIX,example.cn", rules)
        self.assertNotIn("DOMAIN,www.qq.com", rules)
        self.assertNotIn("DOMAIN,only.example.net", rules)
        ip = [l for l in (dist / "CN_IP.list").read_text().splitlines() if not l.startswith("#")]
        self.assertEqual(ip, ["IP-CIDR,1.0.1.0/24,no-resolve", "IP-CIDR6,2001:250::/30,no-resolve"])

    def test_aborts_on_small_source(self):
        with self.assertRaises(SystemExit):
            self.run_build(min_domains=100)

    def test_aborts_on_invalid_custom_rule(self):
        with self.assertRaises(SystemExit):
            self.run_build(direct="IP-CIDR,1.2.3.0/24\n")

    def test_aborts_on_exact_rule_in_exclude(self):
        with self.assertRaises(SystemExit):
            self.run_build(exclude="DOMAIN,www.jd.com\n")


if __name__ == "__main__":
    unittest.main()
