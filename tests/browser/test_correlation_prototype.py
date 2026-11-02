import unittest

from src.browser.correlation_prototype import Observation, correlate_synthetic


class SyntheticCorrelationTests(unittest.TestCase):
    def sample(self, **changes):
        data = dict(profile_token='profile-a', session_token='session-a',
                    request_token='request-a', browser_profile_token='profile-a',
                    browser_session_token='session-a', browser_request_token='request-a',
                    response_session_token='session-a', response_request_token='request-a',
                    proxy_session_token='session-a', proxy_request_token='request-a',
                    target_host='claude.ai', reported_ip='203.0.113.9',
                    expected_ip='203.0.113.9', observed_at=100.0, now=102.0,
                    matching_proxy_connections=1)
        data.update(changes)
        return Observation(**data)

    def test_matching_synthetic_events_only_yield_candidate(self):
        result = correlate_synthetic(self.sample())
        self.assertEqual(result.diagnostic, 'candidate')
        self.assertEqual(result.identity_status, 'unconfirmed')
        self.assertEqual(result.proxy_status, 'unconfirmed')
        self.assertFalse(result.may_launch)

    def test_missing_or_conflicting_context_never_becomes_candidate(self):
        cases = [dict(browser_profile_token='other'), dict(response_session_token='other'),
                 dict(proxy_request_token='other'), dict(target_host='example.com'),
                 dict(reported_ip='203.0.113.10'), dict(matching_proxy_connections=0),
                 dict(matching_proxy_connections=2), dict(request_token='')]
        for update in cases:
            with self.subTest(update=update):
                result = correlate_synthetic(self.sample(**update))
                self.assertEqual(result.diagnostic, 'rejected')
                self.assertFalse(result.may_launch)

    def test_stale_or_future_observations_rejected(self):
        for t in [79.0, 103.0]:
            result = correlate_synthetic(self.sample(observed_at=t))
            self.assertEqual(result.diagnostic, 'rejected')
            self.assertFalse(result.may_launch)

    def test_observation_repr_does_not_leak_ips_or_tokens(self):
        output = repr(self.sample())
        self.assertNotIn('203.0.113.9', output)
        self.assertNotIn('profile-a', output)


if __name__ == '__main__':
    unittest.main()
