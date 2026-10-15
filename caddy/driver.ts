/** Bounded process and protected-path checks shared by the SSH wrapper and helper. */
export const hostSafety = String.raw`
import os,pathlib,selectors,signal,stat,subprocess,time

def protected_path(value,kind='file',owner=0):
    path=pathlib.Path(value)
    if not path.is_absolute() or str(path)!=value or '..' in path.parts:
        raise RuntimeError('Expected a canonical absolute protected path')
    for component in [*reversed(path.parents),path]:
        meta=component.lstat()
        if stat.S_ISLNK(meta.st_mode): raise RuntimeError('Protected path must not contain symlinks')
        if meta.st_uid not in (0,owner) or meta.st_mode & 0o022:
            raise RuntimeError('Protected path must be owned by its privileged operator and not writable by others')
        final=component==path
        expected=stat.S_ISDIR(meta.st_mode) if not final or kind=='directory' else stat.S_ISREG(meta.st_mode)
        if not expected: raise RuntimeError('Protected path has an unsupported file type')
        if final and kind=='executable' and not meta.st_mode & 0o111:
            raise RuntimeError('Protected executable lacks execute permission')
    return meta

def bounded_process(argv,input=None,timeout=45,limit=16384):
    # Stderr is never retained: Caddy diagnostics can contain credentials.
    deadline=time.monotonic()+timeout
    p=subprocess.Popen(argv,stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    output=bytearray(); pending=memoryview(input or b''); selector=selectors.DefaultSelector()
    try:
        os.set_blocking(p.stdout.fileno(),False); selector.register(p.stdout,selectors.EVENT_READ)
        if p.stdin is not None:
            os.set_blocking(p.stdin.fileno(),False)
            if pending: selector.register(p.stdin,selectors.EVENT_WRITE)
            else: p.stdin.close()
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0: raise RuntimeError('Command deadline exceeded; diagnostics withheld')
            for key,_ in selector.select(min(remaining,0.1)):
                if key.fileobj is p.stdin:
                    try: count=os.write(p.stdin.fileno(),pending[:4096])
                    except BrokenPipeError: count=len(pending)
                    pending=pending[count:]
                    if not pending: selector.unregister(p.stdin);p.stdin.close()
                else:
                    chunk=os.read(p.stdout.fileno(),4096)
                    if not chunk: selector.unregister(p.stdout);p.stdout.close()
                    else:
                        if len(output)+len(chunk)>limit: raise RuntimeError('Command output limit exceeded; diagnostics withheld')
                        output.extend(chunk)
        try: code=p.wait(timeout=max(0,deadline-time.monotonic()))
        except subprocess.TimeoutExpired: raise RuntimeError('Command deadline exceeded; diagnostics withheld') from None
        return subprocess.CompletedProcess(argv,code,bytes(output),b'')
    finally:
        selector.close()
        # The privileged helper can kill its command group. An unprivileged
        # wrapper cannot promise cancellation of an already elevated helper.
        try: os.killpg(p.pid,signal.SIGKILL)
        except (ProcessLookupError,PermissionError): pass
        for pipe in (p.stdin,p.stdout):
            if pipe is not None: pipe.close()
        try: p.wait(timeout=1)
        except subprocess.TimeoutExpired: pass
`;

/** Remote Caddyfile transaction, executed by the existing Swamp SSH model. */
export const driver = hostSafety + String.raw`
import os,sys,json,re,hashlib,pathlib,tempfile,subprocess,fcntl,shutil,uuid,ipaddress

def digest(value): return hashlib.sha256(value).hexdigest()
def file_identity(meta):
    return (meta.st_dev,meta.st_ino,meta.st_uid,meta.st_gid,meta.st_mode,
            meta.st_nlink,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns)

def require_unchanged(path,meta,expected):
    # All administrative writers must honor the same flock. These checks
    # detect observed drift; they are not CAS against a writer ignoring it.
    if path.is_symlink() or file_identity(path.lstat())!=file_identity(meta) or digest(path.read_bytes())!=expected:
        raise RuntimeError('Concurrent configuration content or metadata edit; refusing replacement')

def client_networks(values):
    if not isinstance(values,list) or not 1<=len(values)<=32: raise RuntimeError('One to 32 client networks required')
    if not all(isinstance(c,str) for c in values): raise RuntimeError('Client networks must be CIDR strings')
    networks=[ipaddress.ip_network(c,strict=True) for c in values]
    for version in (4,6):
        if any(n.prefixlen==0 for n in ipaddress.collapse_addresses(n for n in networks if n.version==version)):
            raise RuntimeError('Explicit non-universal client networks required')
    return [str(n) for n in networks]

def run(argv):
    p=bounded_process(argv)
    if p.returncode: raise RuntimeError('Command failed: '+pathlib.Path(argv[0]).name+' '+argv[1]+'; output withheld because Caddy diagnostics may contain secrets')
    return p.stdout.decode().strip()

def service_active(binary):
    p=bounded_process([binary,'is-active','caddy'],limit=256)
    state=p.stdout.decode().strip()
    if p.returncode==0 and state=='active': return True
    if p.returncode==3 and state in ('inactive','failed','activating','deactivating','reloading'): return False
    raise RuntimeError('Unable to determine Caddy service state; diagnostics withheld')

def render_block(name,host,upstream,networks,scheme='http',ca=None):
    proxy=['        reverse_proxy '+upstream]
    if scheme=='https':
        proxy=['        reverse_proxy https://'+upstream+' {',
            '            transport http {','                tls_trust_pool file '+ca,
            '            }','        }']
    return '\n'.join(['    # BEGIN swamp-caddy '+name,'    @swamp_'+name+' host '+host,'    handle @swamp_'+name+' {',
        '        @outside_'+name+' not remote_ip '+' '.join(networks),
        '        respond @outside_'+name+' "Forbidden" 403']+proxy+['    }','    # END swamp-caddy '+name])+'\n'

def managed_blocks(text):
    # Only complete, canonical blocks immediately following a plain wildcard
    # header are owned. Markers never authorize deletion of arbitrary spans.
    lines=text.splitlines(keepends=True); result={}; opened=None; offset=0
    for line in lines:
        if re.search(r'#\s*(?:BEGIN|END)\s+swamp-caddy',line):
            marker=re.fullmatch(r'    # (BEGIN|END) swamp-caddy ([a-z][a-z0-9_]{0,31})\n',line)
            if not marker: raise RuntimeError('Malformed managed markers')
            side,name=marker.groups()
            if side=='BEGIN':
                if opened is not None or name in result: raise RuntimeError('Malformed managed markers')
                opened=(name,offset)
            else:
                if opened is None or opened[0]!=name: raise RuntimeError('Malformed managed markers')
                start=opened[1];stop=offset+len(line);body=text[start:stop];parts=body.splitlines()
                match=re.fullmatch(r'    @swamp_'+re.escape(name)+r' host ([a-z0-9.-]+)',parts[1]) if len(parts) in (8,12) else None
                if not match: raise RuntimeError('Malformed managed markers or block')
                host=match[1]
                networks=parts[3].removeprefix('        @outside_'+name+' not remote_ip ').split(' ')
                try:
                    networks=client_networks(networks)
                except (ValueError,RuntimeError): raise RuntimeError('Malformed managed markers or networks')
                proxy=re.fullmatch(r'        reverse_proxy (https://)?((?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5})( \{)?',parts[5])
                if not proxy: raise RuntimeError('Malformed managed markers or proxy')
                scheme='https' if proxy[1] else 'http'
                ca=parts[7].removeprefix('                tls_trust_pool file ') if scheme=='https' and len(parts)==12 else None
                if body!=render_block(name,host,proxy[2],networks,scheme,ca): raise RuntimeError('Malformed managed markers or block')
                anchors=list(re.finditer(r'^\*\.([a-z0-9.-]+)\s*\{[ \t]*\n',text[:start],re.M))
                if not anchors: raise RuntimeError('Managed markers outside wildcard header')
                anchor=anchors[-1];prefix=text[anchor.end():start]
                for other_start,other_stop,_,_ in result.values():
                    if other_start>=anchor.end(): prefix=prefix.replace(text[other_start:other_stop],'',1)
                zone=anchor[1]
                if prefix.strip() or not host.endswith('.'+zone) or host.count('.')!=zone.count('.')+1: raise RuntimeError('Managed markers outside owning wildcard header')
                result[name]=(start,stop,host,zone);opened=None
        offset+=len(line)
    if opened is not None: raise RuntimeError('Malformed managed markers')
    return result

def validate_ca_file(value):
    if not isinstance(value,str) or not re.fullmatch(r'/etc/caddy/trust/[a-zA-Z0-9_-]+\.pem',value):
        raise RuntimeError('CA file must be a PEM under /etc/caddy/trust')
    ca=pathlib.Path(value)
    for component in [ca.parent,ca]:
        if component.is_symlink(): raise RuntimeError('CA path must not contain symlinks')
        meta=component.stat()
        if meta.st_uid!=0 or meta.st_mode & 0o022:
            raise RuntimeError('CA directory and file must be root-owned and not writable by others')
    if not ca.is_file(): raise RuntimeError('CA must be a regular file')
    if ca.stat().st_size>65536: raise RuntimeError('CA file exceeds 64 KiB')
    pem=ca.read_text()
    if 'PRIVATE KEY' in pem or not pem.startswith('-----BEGIN CERTIFICATE-----'):
        raise RuntimeError('CA file must contain public certificates only')
    return value

def transaction(p):
    path=pathlib.Path(p['configPath'])
    if not path.is_absolute() or path.name!='Caddyfile' or path.is_symlink() or not path.is_file():
        raise RuntimeError('Expected a regular absolute Caddyfile path')
    if p['action'] not in ('inspect','plan','apply','remove'): raise RuntimeError('Invalid action')
    # main() requires root; current-UID ownership also permits disposable
    # unprivileged transaction fixtures without a production bypass flag.
    protected_path(str(path),owner=os.geteuid())
    protected_path(p['systemctlBinary'],'executable',os.geteuid())
    if p['action']!='inspect': protected_path(p['caddyBinary'],'executable',os.geteuid())
    lockpath=path.parent/'.swamp-caddy.lock'
    fd=os.open(str(lockpath),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        protected_path(str(lockpath),owner=os.geteuid())
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with open(path,'rb') as source:
            meta=os.fstat(source.fileno());original=source.read(1048577)
        before=digest(original)
        if len(original)>1048576: raise RuntimeError('Caddyfile exceeds 1 MiB limit')
        active=service_active(p['systemctlBinary'])
        result={'requestId':p['requestId'],'action':p['action'],'beforeSha256':before,
                'afterSha256':before,'changed':False,'validated':False,'serviceActive':active,
                'backupPath':None,'route':None}
        if p['action']=='inspect': return result
        if not active: raise RuntimeError('Caddy must already be active')
        if p.get('expectedSha256')!=before: raise RuntimeError('Caddyfile changed since inspection; inspect and plan again')
        name=p['name']; host=p['hostname']; zone=p['wildcardDomain']
        dns=r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+'
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,31}',name): raise RuntimeError('Invalid route name')
        if not re.fullmatch(dns,host) or not re.fullmatch(dns,zone) or host.count('.')!=zone.count('.')+1 or not host.endswith('.'+zone): raise RuntimeError('Host must be one label beneath wildcard domain')
        begin='    # BEGIN swamp-caddy '+name
        end='    # END swamp-caddy '+name
        text=original.decode('utf-8')
        if '\r' in text: raise RuntimeError('Normalize CRLF manually before managing routes')
        if re.search(r'^\s*import\s',text,re.M): raise RuntimeError('Imported configuration needs an import-aware transaction; refusing to validate a partial configuration')
        blocks=managed_blocks(text)
        if name in blocks:
            start,stop,owned_host,owned_zone=blocks[name]
            if owned_host!=host or owned_zone!=zone:
                raise RuntimeError('Managed route identity differs; inspect before removal or replacement')
            text=text[:start]+text[stop:]
        if p['action']=='remove':
            candidate=text.encode()
            result.update(afterSha256=digest(candidate),changed=candidate!=original,route=None)
        else:
            upstream=p['upstream']
            if not re.fullmatch(r'(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}',upstream) or not 0<int(upstream.rsplit(':',1)[1])<65536: raise RuntimeError('Upstream must be host:port without credentials or directives')
            scheme=p.get('upstreamScheme','https'); ca=p.get('upstreamCaFile')
            if scheme not in ('http','https'): raise RuntimeError('Invalid upstream scheme')
            if scheme=='https': validate_ca_file(ca)
            elif ca is not None: raise RuntimeError('HTTP upstream must not specify a CA file')
            networks=client_networks(p.get('allowedCidrs'))
            if re.search(r'(?<![a-zA-Z0-9_.-])'+re.escape(host)+r'\.?(?![a-zA-Z0-9_.-])',text,re.I): raise RuntimeError('Host already occurs outside this managed route')
            anchor=re.compile(r'^\*\.'+re.escape(zone)+r'\s*\{[ \t]*$',re.M)
            matches=list(anchor.finditer(text))
            if len(matches)!=1: raise RuntimeError('Expected exactly one plain wildcard site header; inspect layout before adapting')
            block=render_block(name,host,upstream,networks,scheme,ca)
            insert=matches[0].end()+1
            if text[matches[0].end():insert]!='\n': raise RuntimeError('Wildcard header needs a newline')
            candidate=(text[:insert]+block+text[insert:]).encode()
            result.update(afterSha256=digest(candidate),changed=candidate!=original,route=block)
        with tempfile.TemporaryDirectory(prefix='.swamp-caddy-',dir=path.parent) as temp:
            staged=pathlib.Path(temp)/'Caddyfile'; staged.write_bytes(candidate); staged.chmod(0o600)
            # Validation requires real module provisioning, not only adaptation.
            run([p['caddyBinary'],'validate','--config',str(staged),'--adapter','caddyfile'])
            result['validated']=True
            require_unchanged(path,meta,before)
            if p['action']=='plan': return result
            if not result['changed']:
                # Reconcile a previous interrupted disk replacement, even when
                # desired bytes already match. This never restarts the service.
                run([p['systemctlBinary'],'reload','caddy'])
                if not service_active(p['systemctlBinary']): raise RuntimeError('Caddy inactive after reload')
                require_unchanged(path,meta,before)
                return result
            backups=path.parent/'.swamp-caddy-backups'
            if backups.is_symlink(): raise RuntimeError('Backup directory must not be a symlink')
            backups.mkdir(mode=0o700,exist_ok=True)
            protected_path(str(backups),'directory',os.geteuid())
            if backups.stat().st_mode & 0o077: raise RuntimeError('Backup directory must be private')
            # Reserve one slot before writing, so repeated failed reloads also
            # retain at most five backups. Never prune foreign files/symlinks.
            owned=[]
            for entry in backups.iterdir():
                if re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}\.Caddyfile',entry.name):
                    info=entry.lstat()
                    if stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode & 0o077:
                        owned.append(entry)
            owned.sort(key=lambda entry:(entry.stat().st_mtime_ns,entry.name),reverse=True)
            for entry in owned[4:]: entry.unlink()
            backup=backups/(before+'-'+uuid.uuid4().hex+'.Caddyfile')
            with open(backup,'xb') as f:
                os.chmod(backup,0o600); f.write(original); f.flush(); os.fsync(f.fileno())
            if digest(backup.read_bytes())!=before: raise RuntimeError('Backup verification failed')
            result['backupPath']=str(backup)
            os.chown(staged,meta.st_uid,meta.st_gid); os.chmod(staged,meta.st_mode & 0o777)
            with open(staged,'rb') as f: os.fsync(f.fileno())
            require_unchanged(path,meta,before)
            os.replace(staged,path)
            applied_meta=path.lstat()
            try:
                run([p['systemctlBinary'],'reload','caddy'])
                if not service_active(p['systemctlBinary']): raise RuntimeError('Caddy inactive after reload')
                require_unchanged(path,applied_meta,result['afterSha256'])
            except Exception as error:
                require_unchanged(path,applied_meta,result['afterSha256'])
                staged.write_bytes(original); os.chown(staged,meta.st_uid,meta.st_gid); staged.chmod(meta.st_mode & 0o777)
                require_unchanged(path,applied_meta,result['afterSha256'])
                os.replace(staged,path)
                restored_meta=path.lstat()
                try:
                    run([p['systemctlBinary'],'reload','caddy'])
                    if not service_active(p['systemctlBinary']): raise RuntimeError('Inactive')
                    require_unchanged(path,restored_meta,before)
                except Exception as rollback_error: raise RuntimeError('Rollback/reload could not be verified; preserved backup: '+str(backup)) from rollback_error
                raise RuntimeError('Apply failed; original Caddyfile restored and reloaded') from error
        return result
`;
