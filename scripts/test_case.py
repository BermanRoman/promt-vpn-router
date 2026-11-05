"""Synthetic offline tests; no infrastructure, network, or secrets are used."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import case


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'case'
        self.assertEqual(self.cli('init'), 0)
        self.project = json.loads((self.root / 'project.json').read_text())
        self.project.update(router=True, exit_mode='split-exit', adfilter_enabled=True)
        self.save_project()
        (self.root / 'evidence/proof.txt').write_text('Synthetic observation only.\n')

    def cli(self, command, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return case.main([command, str(self.root), *args])

    def save_project(self):
        (self.root / 'project.json').write_text(json.dumps(self.project))

    def record(self, gate, status='pass', evidence='evidence/proof.txt', duration=None):
        args = [gate, status, '--note', 'Synthetic observation']
        if evidence:
            args += ['--evidence', evidence]
        if duration is not None:
            args += ['--duration-seconds', str(duration)]
        return self.cli('record', *args)

    def complete(self):
        for gate in case.GATES:
            skipped = case.disabled(self.project, gate)
            self.assertEqual(self.record(gate, 'skipped' if skipped else 'pass',
                                         duration=300 if gate == 'wan_stable' and not skipped else None), 0, gate)

    def test_complete_split_router(self):
        self.complete()
        self.assertEqual(self.cli('check'), 0)

    def test_single_no_router_explicit_skips(self):
        self.project.update(router=False, exit_mode='single-exit', adfilter_enabled=False)
        self.save_project()
        self.assertEqual(self.record('router_exact_revision'), 2)
        self.assertEqual(self.cli('check'), 1)
        self.complete()
        self.assertEqual(self.cli('check'), 0)
        state = json.loads((self.root / 'state.json').read_text())
        for stage, gates in case.STAGES.items():
            if stage.startswith('router_'):
                for gate in gates:
                    self.assertEqual(state['records'][gate]['status'], 'skipped')

    def test_selection_blocks_design_until_purchase_readiness_verified(self):
        for stage in ('intake', 'inventory'):
            for gate in case.STAGES[stage]:
                self.assertEqual(self.record(gate), 0)
        self.assertEqual(self.record('topology_approved'), 2)
        self.assertEqual(self.record('router_exact_revision', 'unknown'), 0)
        for gate in ('router_flash_compatibility', 'router_signed_firmware'):
            self.assertEqual(self.record(gate), 0)
        self.assertEqual(self.record('topology_approved'), 2)
        self.assertEqual(self.record('router_exact_revision', 'fail'), 0)
        self.assertEqual(self.record('topology_approved'), 2)
        self.assertEqual(self.record('router_exact_revision'), 0)
        self.assertEqual(self.record('topology_approved'), 0)
        # Losing revision evidence invalidates recorded design readiness as well.
        self.assertEqual(self.record('router_exact_revision', 'unknown'), 0)
        project, state = case.load(self.root)
        errors, complete = case.audit(self.root, project, state)
        self.assertNotIn('router_selection', complete)
        self.assertIn('topology_approved: earlier stage incomplete', errors)

    def test_fail_unknown_missing_never_complete(self):
        self.assertEqual(self.cli('check'), 1)
        for status in ('fail', 'unknown'):
            self.assertEqual(self.record('scope_authorized', status), 0)
            self.assertEqual(self.cli('check'), 1)
            self.assertEqual(self.record('current_inventory'), 2)

    def test_wrong_dependency_and_required_skip(self):
        self.assertEqual(self.record('handover_accepted'), 2)
        self.assertEqual(self.record('scope_authorized', 'skipped'), 2)

    def test_missing_evidence_and_path_escape(self):
        outside = Path(self.temp.name) / 'outside.txt'
        outside.write_text('Synthetic')
        (self.root / 'evidence/link.txt').symlink_to(outside)
        for path in (None, 'missing.txt', '../outside.txt', str(outside), 'evidence/link.txt', 'state.json', 'evidence'):
            self.assertEqual(self.record('scope_authorized', evidence=path), 2, path)

    def test_duration_and_removed_evidence(self):
        self.complete()
        for duration in (299, -1, 'nan', 'inf'):
            self.assertEqual(self.record('wan_stable', duration=duration), 2)
        (self.root / 'evidence/proof.txt').unlink()
        self.assertEqual(self.cli('check'), 1)

    def test_invalidated_dependency(self):
        self.complete()
        self.assertEqual(self.record('ssh_hostkey_independent', 'fail'), 0)
        self.assertEqual(self.cli('check'), 1)

    def test_init_refuses_existing_and_permissions(self):
        before = (self.root / 'state.json').read_bytes()
        self.assertEqual(self.cli('init'), 2)
        self.assertEqual((self.root / 'state.json').read_bytes(), before)
        if os.name == 'posix':
            self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.root / 'state.json').stat().st_mode & 0o777, 0o600)

    def test_unset_choice_and_unexpected_secret_field(self):
        self.project['router'] = None
        self.save_project()
        self.assertEqual(self.cli('check'), 2)
        self.project['router'] = True
        self.project['password'] = 'synthetic-forbidden-field'
        self.save_project()
        self.assertEqual(self.cli('check'), 2)

    def test_tampered_record(self):
        self.complete()
        state = json.loads((self.root / 'state.json').read_text())
        state['records']['scope_authorized']['status'] = 'unknown'
        (self.root / 'state.json').write_text(json.dumps(state))
        self.assertEqual(self.cli('check'), 1)

    def test_malformed_record_does_not_crash(self):
        state = {'schema_version': 1, 'records': {'scope_authorized': ['invalid']}}
        (self.root / 'state.json').write_text(json.dumps(state))
        self.assertEqual(self.cli('check'), 1)

    def test_missing_skip_reason(self):
        self.project['router'] = False
        self.save_project()
        self.assertEqual(self.cli('record', 'router_exact_revision', 'skipped', '--note', ''), 2)


if __name__ == '__main__':
    unittest.main()
