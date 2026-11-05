#!/usr/bin/env python3
"""Offline completeness ledger. Records are assertions, never automatic proof."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from datetime import datetime, timezone


STAGES = {
    'intake': ['scope_authorized', 'requirements_confirmed'],
    'inventory': ['current_inventory', 'existing_operations_reviewed'],
    'router_selection': ['router_exact_revision', 'router_flash_compatibility',
                         'router_signed_firmware'],
    'design': ['topology_approved', 'rollback_plan'],
    'access': ['ssh_hostkey_independent', 'ssh_authentication'],
    'servers': ['backups_verified', 'server_core', 'special_exit_isolation'],
    'client_pilot': ['actual_client_ru_direct', 'actual_client_foreign_exit',
                     'actual_client_special_exit', 'failed_special_closed',
                     'other_user_denied', 'adfilter', 'rule_update'],
    'router_recovery': ['router_recovery_link', 'router_backup_restore'],
    'router_wan': ['wan_real_isp', 'wan_stable', 'wan_dns', 'wan_tls', 'wan_mtu'],
    'router_vpn': ['router_ru_direct', 'router_foreign_exit', 'router_special_exit',
                   'router_failed_special_closed', 'router_other_user_denied',
                   'router_adfilter', 'router_rule_update'],
    'cutover': ['cutover_authorized', 'cutover_rollback_ready', 'cutover_actual_path'],
    'acceptance': ['actual_client_acceptance', 'recovery_acceptance'],
    'handover': ['handover_limits', 'handover_operations', 'handover_accepted'],
}
GATES = {gate: stage for stage, gates in STAGES.items() for gate in gates}
SPECIAL = {'special_exit_isolation', 'actual_client_special_exit',
           'failed_special_closed', 'other_user_denied', 'router_special_exit',
           'router_failed_special_closed', 'router_other_user_denied'}
ADS = {'adfilter', 'rule_update', 'router_adfilter', 'router_rule_update'}
PROJECT_KEYS = {'schema_version', 'case_name', 'router', 'exit_mode',
                'adfilter_enabled', 'provider_defaults', 'endpoints', 'secret_file_refs'}


def read_json(path):
    with path.open(encoding='utf-8') as handle:
        return json.load(handle)


def write_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.ledger-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(root):
    project = read_json(root / 'project.json')
    state = read_json(root / 'state.json')
    if not isinstance(project, dict) or not isinstance(state, dict):
        raise ValueError('project and state must be objects')
    if set(project) != PROJECT_KEYS or project.get('schema_version') != 1:
        raise ValueError('invalid project schema or unknown project fields')
    if not isinstance(project['case_name'], str) or not project['case_name'].strip():
        raise ValueError('case_name must be nonempty text')
    if type(project['router']) is not bool:
        raise ValueError('set router explicitly to true or false')
    if project['exit_mode'] not in ('single-exit', 'split-exit'):
        raise ValueError('set exit_mode to single-exit or split-exit')
    if type(project['adfilter_enabled']) is not bool:
        raise ValueError('set adfilter_enabled explicitly to true or false')
    if (not isinstance(project['provider_defaults'], dict)
            or set(project['provider_defaults']) != {'domain_dns', 'panel_vps', 'primary_exit', 'router_model'}
            or not all(isinstance(v, str) for v in project['provider_defaults'].values())):
        raise ValueError('invalid provider_defaults labels')
    if not isinstance(project['endpoints'], list):
        raise ValueError('endpoints must be a list')
    for endpoint in project['endpoints']:
        if (not isinstance(endpoint, dict) or set(endpoint) != {'role', 'host'}
                or not all(isinstance(v, str) and v.strip() for v in endpoint.values())):
            raise ValueError('each endpoint permits only nonempty role and host')
    if (not isinstance(project['secret_file_refs'], list)
            or not all(isinstance(p, str) and p.strip() and '://' not in p
                       for p in project['secret_file_refs'])):
        raise ValueError('secret_file_refs permits local file paths only')
    if (set(state) != {'schema_version', 'records'} or state['schema_version'] != 1
            or not isinstance(state['records'], dict)
            or set(state['records']) - set(GATES)):
        raise ValueError('invalid state schema or unknown gate')
    return project, state


def disabled(project, gate):
    if not project['router'] and GATES[gate].startswith('router_'):
        return 'no-router'
    if project['exit_mode'] == 'single-exit' and gate in SPECIAL:
        return 'single-exit'
    if not project['adfilter_enabled'] and gate in ADS:
        return 'adfilter disabled'
    return None


def evidence_error(root, name):
    if not isinstance(name, str) or not name.strip():
        return 'invalid evidence path'
    path = Path(name)
    if path.is_absolute() or '..' in path.parts:
        return 'evidence must be a relative path inside the case'
    try:
        resolved = (root / path).resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (ValueError, OSError, RuntimeError):
        return 'missing or escaping evidence'
    if not resolved.is_file():
        return 'evidence must be a regular file'
    if resolved in {(root / 'project.json').resolve(), (root / 'state.json').resolve()}:
        return 'ledger files are not evidence'
    return None


def record_errors(root, project, gate, record):
    if not isinstance(record, dict):
        return ['record must be an object']
    if set(record) != {'status', 'evidence', 'note', 'duration_seconds', 'recorded_at'}:
        return ['invalid record fields']
    errors = []
    status = record['status']
    if status not in ('pass', 'fail', 'unknown', 'skipped'):
        errors.append('invalid status')
    if not isinstance(record['note'], str) or not isinstance(record['recorded_at'], str):
        errors.append('note and recorded_at must be text')
    elif not record['note'].strip():
        errors.append('a sanitized observation or skip reason is required')
    reason = disabled(project, gate)
    if reason and status != 'skipped':
        errors.append('requires explicit skipped record: ' + reason)
    if not reason and status == 'skipped':
        errors.append('required gate cannot be skipped')
    if not isinstance(record['evidence'], list):
        errors.append('evidence must be a list')
    else:
        if status in ('pass', 'fail') and not record['evidence']:
            errors.append('pass/fail requires a local evidence file')
        for name in record['evidence']:
            error = evidence_error(root, name)
            if error:
                errors.append(error)
    duration = record['duration_seconds']
    if duration is not None and (type(duration) not in (int, float)
                                 or not 0 <= duration < float('inf')):
        errors.append('duration must be a finite nonnegative number')
    if gate == 'wan_stable' and status == 'pass':
        if type(duration) not in (int, float) or not 300 <= duration < float('inf'):
            errors.append('real ISP WAN needs at least 300 measured seconds')
    elif duration is not None:
        errors.append('duration is only supported for a passed wan_stable gate')
    return errors


def audit(root, project, state):
    errors, complete = [], []
    prior_complete = True
    for stage, gates in STAGES.items():
        stage_complete = True
        for gate in gates:
            record = state['records'].get(gate)
            if record is None:
                errors.append(gate + ': missing')
                stage_complete = False
                continue
            issues = record_errors(root, project, gate, record)
            errors.extend(gate + ': ' + issue for issue in issues)
            passed = not issues and record['status'] in ('pass', 'skipped')
            if not passed:
                stage_complete = False
                if not issues:
                    errors.append(gate + ': ' + record['status'])
            if isinstance(record, dict) and record.get('status') == 'pass' and not prior_complete:
                errors.append(gate + ': earlier stage incomplete')
        if stage_complete and prior_complete:
            complete.append(stage)
        prior_complete = prior_complete and stage_complete
    return errors, complete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('directory', type=Path)
    for command in ('status', 'check', 'record'):
        command_parser = sub.add_parser(command)
        command_parser.add_argument('directory', type=Path)
        if command == 'record':
            command_parser.add_argument('gate', choices=list(GATES))
            command_parser.add_argument('status', choices=['pass', 'fail', 'unknown', 'skipped'])
            command_parser.add_argument('--evidence', action='append', default=[])
            command_parser.add_argument('--note', required=True)
            command_parser.add_argument('--duration-seconds', type=float)
    args = parser.parse_args(argv)
    root = args.directory.absolute()
    try:
        if args.command == 'init':
            template = Path(__file__).resolve().parent.parent / 'assets/project.example.json'
            project = read_json(template)
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
            write_json(root / 'project.json', project)
            write_json(root / 'state.json', {'schema_version': 1, 'records': {}})
            (root / 'evidence').mkdir(mode=0o700)
            print('Initialized local case. Set explicit project choices before recording.')
            return 0
        project, state = load(root)
        if args.command == 'record':
            record = {'status': args.status, 'evidence': args.evidence,
                      'note': args.note, 'duration_seconds': args.duration_seconds,
                      'recorded_at': datetime.now(timezone.utc).isoformat()}
            errors = record_errors(root, project, args.gate, record)
            if errors:
                raise ValueError('; '.join(errors))
            if args.status == 'pass':
                # A later pass cannot be stored before all earlier stages close.
                _, complete = audit(root, project, state)
                index = list(STAGES).index(GATES[args.gate])
                if len(complete) < index:
                    raise ValueError('earlier stage incomplete')
            write_json(root / 'state.json', dict(state, records=dict(state['records'], **{args.gate: record})))
            print('Recorded manual assertion; evidence truth is not verified.')
            return 0
        errors, complete = audit(root, project, state)
        print('Complete stages: {}/{}'.format(len(complete), len(STAGES)))
        print('Manual records only: completeness does not prove real infrastructure behavior.')
        if args.command == 'check':
            for error in errors:
                print(error)
            return 1 if errors else 0
        for stage, gates in STAGES.items():
            counts = sum(g in state['records'] for g in gates)
            print('{}: {} ({}/{})'.format(stage, 'complete' if stage in complete else 'pending', counts, len(gates)))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        # Do not echo file contents, supplied paths, or OS error strings.
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'cannot read/write local case or invalid data'
        print('Error: ' + message, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
