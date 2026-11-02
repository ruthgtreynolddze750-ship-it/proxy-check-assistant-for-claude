"""Fixed offline WFP lifecycle simulation; no native WFP bindings or writes."""
import argparse
import json
from uuid import uuid4


_CASES = ('success', 'add_failure', 'commit_failure', 'readback_mismatch', 'delete_failure')


class FixtureBackend:
    def __init__(self, scenario):
        self.scenario = scenario
        self.events = []
        self.object = None

    def begin(self):
        self.events.append('begin')

    def add(self, rule):
        self.events.append('add')
        if self.scenario == 'add_failure':
            raise RuntimeError('synthetic_add_failure')
        self.object = dict(rule)

    def commit(self):
        self.events.append('commit')
        if self.scenario == 'commit_failure':
            raise RuntimeError('synthetic_commit_failure')

    def abort(self):
        self.events.append('abort')
        self.object = None

    def readback(self):
        self.events.append('readback')
        if self.scenario == 'readback_mismatch':
            return {**self.object, 'remote_port': 43124}
        return dict(self.object)

    def delete(self, key):
        self.events.append('delete')
        if self.scenario == 'delete_failure':
            raise RuntimeError('synthetic_delete_failure')
        if self.object is None or key != self.object['key']:
            raise RuntimeError('synthetic_ownership_mismatch')
        self.object = None

    def verify_absent(self):
        self.events.append('verify_absent')
        return self.object is None


def run_fixture(scenario):
    if scenario not in _CASES:
        raise ValueError('unknown fixture')
    rule = {'key': str(uuid4()), 'app': 'fixture-project-target-exe',
            'layer': 'ALE_AUTH_CONNECT_V4', 'protocol': 'tcp',
            'remote_address': '127.0.0.1', 'remote_port': 43123,
            'action': 'block', 'session': 'fixture_dynamic'}
    backend = FixtureBackend(scenario)
    result = {'scope': rule, 'system_action': 'none', 'live_write_available': False,
              'protection_effective': 'unknown', 'events': backend.events, 'errors': [],
              'remaining_object': 'unknown'}
    backend.begin()
    try:
        backend.add(rule)
    except RuntimeError as exc:
        result['errors'].append(str(exc))
        backend.abort()
        result.update(result='aborted', remaining_object='fixture_absent')
        return result
    try:
        backend.commit()
    except RuntimeError as exc:
        result['errors'].append(str(exc))
        backend.abort()
        result['result'] = 'commit_unknown'
        return result
    if backend.readback() != rule:
        result['result'] = 'cleanup_refused'
        return result
    try:
        backend.delete(rule['key'])
    except RuntimeError as exc:
        result['errors'].append(str(exc))
        result['result'] = 'cleanup_failed'
        return result
    if not backend.verify_absent():
        result['result'] = 'cleanup_failed'
        return result
    result.update(result='fixture_complete', remaining_object='fixture_absent')
    return result


def main():
    parser = argparse.ArgumentParser(description='固定样本离线生命周期；不调用 Windows WFP。')
    parser.add_argument('--fixture', choices=_CASES, default='success')
    args = parser.parse_args()
    result = run_fixture(args.fixture)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['result'] == 'fixture_complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
