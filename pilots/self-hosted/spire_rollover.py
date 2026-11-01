"""Private administrative SPIRE rollover. Only public authority/bundle data leave stdout."""

import json
import subprocess
import sys
from pathlib import Path

SERVER = '/opt/spire/bin/spire-server'
SOCKET = '/run/kf-spire/private/server.sock'
ROOT = Path('/run/kf-spire/private')


def api(kind, operation, authority=None):
    args = [SERVER, 'localauthority', kind, operation, '-socketPath', SOCKET, '-output', 'json']
    if authority:
        args.extend(['-authorityID', authority])
    result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=15)
    if result.returncode:
        # These local-authority operations carry public IDs, never credentials.
        raise RuntimeError(f'SPIRE {kind} {operation} refused: ' + result.stderr[-1000:])
    return json.loads(result.stdout)


def authority(state, name):
    item = state[name]
    value = item.get('authority_id', item.get('authorityId'))
    if not isinstance(value, str) or not value:
        raise RuntimeError('missing public local authority ID')
    return value


def bundle(name):
    result = subprocess.run([SERVER, 'bundle', 'show', '-socketPath', SOCKET,
                             '-format', 'spiffe'], capture_output=True, check=True, timeout=15)
    value = json.loads(result.stdout)
    if any(set(key) & {'d', 'p', 'q', 'dp', 'dq', 'qi', 'k'} for key in value['keys']):
        raise RuntimeError('SPIRE public bundle includes private material')
    (ROOT / (name + '.json')).write_bytes(result.stdout)
    return value


def main():
    state_path = ROOT / 'rollover-state.json'
    if sys.argv[1:] == ['activate']:
        state = {}
        for kind in ('jwt', 'x509'):
            old = authority(api(kind, 'show'), 'active')
            prepared = api(kind, 'prepare')
            # protojson spelling varies by the CLI formatter; both are public admin output.
            item = prepared.get('prepared_authority', prepared.get('preparedAuthority'))
            if item is None:
                raise RuntimeError('missing prepared authority')
            new = authority({'active': item}, 'active')
            if old == new:
                raise RuntimeError('SPIRE did not prepare a different authority')
            api(kind, 'activate', new)
            if authority(api(kind, 'show'), 'active') != new:
                raise RuntimeError('new SPIRE authority is not active')
            state[kind] = {'old': old, 'new': new}
        bundle('overlap-bundle')
        state_path.write_text(json.dumps(state))
        state_path.chmod(0o600)
        print(json.dumps({'status': 'activated', 'authorities': state}))
    elif sys.argv[1:] in (['revoke'], ['check']):
        state = json.loads(state_path.read_text())
        confirmed = []
        for kind, ids in state.items():
            if authority(api(kind, 'show'), 'active') != ids['new']:
                raise RuntimeError('active SPIRE authority did not survive restart')
            if sys.argv[1:] == ['revoke']:
                try:
                    api(kind, 'revoke', ids['old'])
                except RuntimeError as error:
                    if 'untainted' not in str(error):
                        raise
                    confirmed.append(kind)
                else:
                    raise RuntimeError('SPIRE accepted revocation before taint')
                api(kind, 'taint', ids['old'])
                api(kind, 'revoke', ids['old'])
        value = bundle('retired-bundle')
        jwt_ids = {key['kid'] for key in value['keys'] if key.get('use') == 'jwt-svid'}
        if state['jwt']['new'] not in jwt_ids or state['jwt']['old'] in jwt_ids:
            raise RuntimeError('JWT retirement did not persist')
        proof_path = ROOT / 'retirement-proof.json'
        if sys.argv[1:] == ['revoke']:
            proof_path.write_text(json.dumps({'authorities': state, 'checks': confirmed}))
            proof_path.chmod(0o600)
        proof = json.loads(proof_path.read_text())
        if proof['authorities'] != state or proof['checks'] != ['jwt', 'x509']:
            raise RuntimeError('missing matching retirement precondition proof')
        print(json.dumps({'status': 'retired', 'authorities': state,
                          'sequence': 'prepare/activate/taint/revoke',
                          'untainted_revoke_refused': proof['checks']}))
    else:
        raise SystemExit('expected activate, revoke or check')


if __name__ == '__main__':
    main()
