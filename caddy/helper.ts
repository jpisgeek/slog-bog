/**
 * Entry point appended to the transaction to form `swamp-caddy`, the one
 * root-owned helper the sudoers rule on the edge host names. It reads a JSON
 * payload on stdin, refuses any caller-supplied path (config, caddy or
 * systemctl binaries are fixed here, never taken from the payload), loads the
 * service's environment file so validation provisions the same modules the
 * running service does, runs the transaction, and prints its result.
 *
 * The committed `swamp-caddy.py` must equal `driver + helperMain` byte for
 * byte; a test guards that, and the extension refuses to call an installed
 * helper whose digest differs from the committed file.
 */
export const helperMain = String.raw`

# ---- swamp-caddy: root-owned helper entry ----
ENVFILE='/etc/caddy/caddy.env'
FIXED={'configPath':'/etc/caddy/Caddyfile','caddyBinary':'/usr/bin/caddy','systemctlBinary':'/usr/bin/systemctl'}
ALLOWED={'action','requestId','name','hostname','wildcardDomain','upstream','upstreamScheme','upstreamCaFile','allowedCidrs','expectedSha256'}|set(FIXED)

def _load_env(path):
    try:
        protected_path(path)
        if pathlib.Path(path).stat().st_size>65536: raise RuntimeError('Environment file exceeds limit')
        with open(path) as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith('#') or '=' not in line: continue
                k,v=line.split('=',1); os.environ.setdefault(k.strip(),v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate field')
        result[key]=value
    return result

def main():
    if os.geteuid()!=0:
        print(json.dumps({'error':'swamp-caddy must run as root through sudo'})); return 3
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384: raise ValueError('Oversized payload')
        p=json.loads(raw,object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Unsupported constant')))
    except Exception:
        print(json.dumps({'error':'payload is not JSON'})); return 2
    if not isinstance(p,dict) or not set(p)<=ALLOWED:
        print(json.dumps({'error':'payload carries unexpected keys'})); return 2
    for k,v in FIXED.items():
        if p.get(k,v)!=v:
            print(json.dumps({'error':'refusing caller-supplied '+k})); return 2
        p[k]=v
    if not isinstance(p.get('requestId'),str) or not re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}',p['requestId']):
        print(json.dumps({'error':'invalid requestId'})); return 2
    try:
        if p.get('action')=='inspect':
            if set(p)-set(FIXED)!={'action','requestId'}: raise RuntimeError('Inspection carries unsupported fields')
        elif p.get('action')=='remove':
            if set(p)-set(FIXED)!={'action','requestId','name','hostname','wildcardDomain','expectedSha256'}: raise RuntimeError('Removal carries unsupported fields')
        elif p.get('action') in ('plan','apply'):
            required={'action','requestId','name','hostname','wildcardDomain','upstream','allowedCidrs','expectedSha256'}
            if not required<=set(p): raise RuntimeError('Route fields are incomplete')
        else: raise RuntimeError('Unsupported action')
        _load_env(ENVFILE)
        if p.get('upstreamCaFile') is not None: protected_path(p['upstreamCaFile'])
        result=transaction(p)
    except Exception:
        print(json.dumps({'error':'Caddy operation refused or failed; inspect protected host state before retrying'})); return 1
    print(json.dumps(result)); return 0

if __name__=='__main__':
    sys.exit(main())
`;
