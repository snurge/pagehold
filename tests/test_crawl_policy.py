import unittest

from crawl_policy import (
    estimated_upper_bound_bytes,
    normalize_candidate,
    normalized_site_policy,
    split_patterns,
    url_matches_policy,
)


class CrawlPolicyTests(unittest.TestCase):
    def test_query_normalization_removes_tracking_and_sorts(self):
        self.assertEqual(
            normalize_candidate(
                "HTTPS://Example.COM/news?utm_source=x&b=2&a=1&fbclid=abc#story",
                "normalize",
            ),
            "https://example.com/news?a=1&b=2",
        )
        self.assertEqual(
            normalize_candidate("https://example.com/news?a=1", "drop"),
            "https://example.com/news",
        )

    def test_include_and_exclude_patterns_are_conservative(self):
        self.assertEqual(split_patterns("/news/*, /about\n/contact"), ("/news/*", "/about", "/contact"))
        self.assertTrue(url_matches_policy("https://example.test/news/one", "/news/*", "/news/private/*"))
        self.assertFalse(url_matches_policy("https://example.test/about", "/news/*", ""))
        self.assertFalse(
            url_matches_policy("https://example.test/news/private/a", "/news/*", "/news/private/*")
        )

    def test_policy_values_are_bounded(self):
        policy = normalized_site_policy(
            {
                "request_delay_seconds": -5,
                "request_timeout_seconds": 999,
                "robots_policy": "invalid",
                "query_mode": "invalid",
                "crawl_user_agent": "ExampleArchiver/1.0",
            },
            "default",
        )
        self.assertEqual(policy["request_delay_seconds"], 1.0)
        self.assertEqual(policy["request_timeout_seconds"], 120.0)
        self.assertEqual(policy["robots_policy"], "respect")
        self.assertEqual(policy["query_mode"], "normalize")
        self.assertEqual(policy["user_agent"], "ExampleArchiver/1.0")

    def test_size_ceiling_is_deterministic(self):
        self.assertEqual(estimated_upper_bound_bytes(2, 10, 3, 4), 44)


if __name__ == "__main__":
    unittest.main()
