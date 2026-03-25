"""
Tests for core.aggregator – IOC extraction methods.
"""

import logging
import unittest

from core.aggregator import Aggregator


class TestExtractIPs(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_ipv4(self):
        self.assertEqual(self.agg._extract_ips("Server 192.168.1.1 responded"), ["192.168.1.1"])

    def test_multiple_ips(self):
        text = "Hosts: 10.0.0.1 and 172.16.0.5"
        result = self.agg._extract_ips(text)
        self.assertIn("10.0.0.1", result)
        self.assertIn("172.16.0.5", result)

    def test_loopback_excluded(self):
        self.assertEqual(self.agg._extract_ips("localhost 127.0.0.1"), [])

    def test_multicast_excluded(self):
        self.assertEqual(self.agg._extract_ips("multicast 224.0.0.1"), [])

    def test_reserved_excluded(self):
        self.assertEqual(self.agg._extract_ips("reserved 255.255.255.255"), [])

    def test_zero_prefix_excluded(self):
        self.assertEqual(self.agg._extract_ips("zero 0.0.0.0"), [])

    def test_octet_out_of_range(self):
        self.assertEqual(self.agg._extract_ips("invalid 999.999.999.999"), [])

    def test_empty_string(self):
        self.assertEqual(self.agg._extract_ips(""), [])

    def test_no_ips(self):
        self.assertEqual(self.agg._extract_ips("nothing to see here"), [])


class TestExtractDomains(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_domain(self):
        result = self.agg._extract_domains("callback to evil.com/payload")
        self.assertIn("evil.com", result)

    def test_subdomain(self):
        result = self.agg._extract_domains("cnc.sub.evil.com active")
        self.assertIn("cnc.sub.evil.com", result)

    def test_ip_excluded(self):
        result = self.agg._extract_domains("address 192.168.1.1")
        # IPs should be filtered out
        self.assertNotIn("192.168.1.1", result)

    def test_empty_string(self):
        self.assertEqual(self.agg._extract_domains(""), [])

    def test_single_label_not_matched(self):
        # A single word without TLD should not match
        result = self.agg._extract_domains("just localhost here")
        self.assertEqual(result, [])


class TestExtractURLs(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_http(self):
        result = self.agg._extract_urls("GET http://evil.com/path")
        self.assertIn("http://evil.com/path", result)

    def test_https(self):
        result = self.agg._extract_urls("endpoint https://api.evil.com/data")
        self.assertIn("https://api.evil.com/data", result)

    def test_trailing_punctuation_stripped(self):
        result = self.agg._extract_urls("visit http://evil.com/page.")
        self.assertEqual(result, ["http://evil.com/page"])

    def test_empty_string(self):
        self.assertEqual(self.agg._extract_urls(""), [])

    def test_none_input(self):
        self.assertEqual(self.agg._extract_urls(None), [])

    def test_non_string_input(self):
        self.assertEqual(self.agg._extract_urls(123), [])

    def test_no_urls(self):
        self.assertEqual(self.agg._extract_urls("no urls here"), [])

    def test_multiple_urls(self):
        text = "download http://a.com/f1 and https://b.com/f2"
        result = self.agg._extract_urls(text)
        self.assertEqual(len(result), 2)


class TestExtractFilePaths(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_windows_path(self):
        result = self.agg._extract_file_paths("Created C:\\Windows\\Temp\\mal.exe")
        self.assertIn("C:\\Windows\\Temp\\mal.exe", result)

    def test_unc_path(self):
        result = self.agg._extract_file_paths("accessed \\\\server\\share\\file.txt")
        self.assertTrue(any("\\\\server\\share" in p for p in result))

    def test_empty_string(self):
        self.assertEqual(self.agg._extract_file_paths(""), [])

    def test_no_paths(self):
        self.assertEqual(self.agg._extract_file_paths("no paths here"), [])

    def test_multiple_paths(self):
        text = "C:\\a\\b.exe and D:\\c\\d.dll"
        result = self.agg._extract_file_paths(text)
        self.assertEqual(len(result), 2)


class TestExtractRegistryKeys(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_hkey_local_machine(self):
        result = self.agg._extract_registry_keys("HKEY_LOCAL_MACHINE\\Software\\Test")
        self.assertTrue(any("HKEY_LOCAL_MACHINE" in r for r in result))

    def test_hklm_shorthand(self):
        result = self.agg._extract_registry_keys("HKLM\\Software\\Evil")
        self.assertTrue(any("HKLM" in r for r in result))

    def test_hkcu_shorthand(self):
        result = self.agg._extract_registry_keys("HKCU\\Software\\Run")
        self.assertTrue(any("HKCU" in r for r in result))

    def test_empty_string(self):
        self.assertEqual(self.agg._extract_registry_keys(""), [])

    def test_no_keys(self):
        self.assertEqual(self.agg._extract_registry_keys("no registry keys"), [])

    def test_multiple_keys(self):
        text = "HKLM\\A\\B and HKCU\\C\\D"
        result = self.agg._extract_registry_keys(text)
        self.assertEqual(len(result), 2)


class TestDeduplicatePreserveCase(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_dedup(self):
        result = self.agg._deduplicate_preserve_case(["A", "a", "B", "b"])
        self.assertEqual(result, ["A", "B"])

    def test_preserves_first_case(self):
        result = self.agg._deduplicate_preserve_case(["Evil.COM", "evil.com", "EVIL.com"])
        self.assertEqual(result, ["Evil.COM"])

    def test_empty_list(self):
        self.assertEqual(self.agg._deduplicate_preserve_case([]), [])

    def test_no_duplicates(self):
        result = self.agg._deduplicate_preserve_case(["x", "y", "z"])
        self.assertEqual(result, ["x", "y", "z"])


class TestExtractMitre(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_mitre(self):
        node = {
            "data": [
                {"attributes": {"technique_id": "T1059", "technique": "Command Scripting", "tactic": "Execution"}}
            ]
        }
        result = self.agg._extract_mitre(node)
        self.assertEqual(len(result), 1)
        self.assertIn("T1059", result[0])
        self.assertIn("Command Scripting", result[0])
        self.assertIn("Execution", result[0])

    def test_empty_data(self):
        self.assertEqual(self.agg._extract_mitre({"data": []}), [])

    def test_none_input(self):
        self.assertEqual(self.agg._extract_mitre(None), [])

    def test_non_dict_input(self):
        self.assertEqual(self.agg._extract_mitre("string"), [])

    def test_missing_technique_id(self):
        node = {"data": [{"attributes": {"technique": "Test"}}]}
        self.assertEqual(self.agg._extract_mitre(node), [])

    def test_technique_id_only(self):
        node = {"data": [{"attributes": {"technique_id": "T1055"}}]}
        result = self.agg._extract_mitre(node)
        self.assertEqual(result, ["T1055"])


class TestExtractYaraSigma(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_basic_yara_sigma(self):
        node = {
            "data": {
                "crowdsourced_yara_results": [{"rule_name": "TestYara"}],
                "crowdsourced_sigma_results": [{"rule_name": "TestSigma"}],
            }
        }
        yara, sigma = self.agg._extract_yara_sigma(node)
        self.assertEqual(len(yara), 1)
        self.assertEqual(len(sigma), 1)

    def test_yara_only(self):
        node = {"data": {"crowdsourced_yara_results": [{"rule": "R1"}]}}
        yara, sigma = self.agg._extract_yara_sigma(node)
        self.assertIsNotNone(yara)
        self.assertIsNone(sigma)

    def test_empty_node(self):
        yara, sigma = self.agg._extract_yara_sigma({})
        self.assertIsNone(yara)
        self.assertIsNone(sigma)

    def test_none_node(self):
        yara, sigma = self.agg._extract_yara_sigma(None)
        self.assertIsNone(yara)
        self.assertIsNone(sigma)

    def test_capped_at_50(self):
        node = {
            "data": {
                "crowdsourced_yara_results": [{"r": i} for i in range(100)]
            }
        }
        yara, _ = self.agg._extract_yara_sigma(node)
        self.assertEqual(len(yara), 50)


class TestExtractFileName(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_backslash_path(self):
        self.assertEqual(self.agg._extract_file_name_from_path("C:\\a\\b\\file.exe"), "file.exe")

    def test_forward_slash_path(self):
        self.assertEqual(self.agg._extract_file_name_from_path("/usr/bin/malware"), "malware")

    def test_bare_name(self):
        self.assertEqual(self.agg._extract_file_name_from_path("file.exe"), "file.exe")


class TestBuildStruct(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(logging.getLogger("test"))

    def test_empty_vt_data(self):
        result = self.agg.build_struct({})
        self.assertIn("basic", result)
        self.assertEqual(result["basic"]["detections"], 0)
        self.assertEqual(result["mitre"], [])
        self.assertEqual(result["processes"], [])

    def test_basic_fields(self):
        vt_data = {
            "file_report": {
                "ok": True,
                "data": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 10, "suspicious": 2},
                            "size": 5000,
                            "md5": "abc",
                            "sha256": "def",
                            "type_description": "PE32",
                            "names": ["test.exe"],
                        }
                    }
                }
            }
        }
        result = self.agg.build_struct(vt_data)
        self.assertEqual(result["basic"]["detections"], 12)
        self.assertEqual(result["basic"]["size"], 5000)
        self.assertEqual(result["basic"]["md5"], "abc")

    def test_missing_stats_defaults_to_zero(self):
        vt_data = {
            "file_report": {
                "ok": True,
                "data": {"data": {"attributes": {}}}
            }
        }
        result = self.agg.build_struct(vt_data)
        self.assertEqual(result["basic"]["detections"], 0)


if __name__ == "__main__":
    unittest.main()
