/** Remote Caddyfile transaction, executed by the existing Swamp SSH model. */
export const driver = String.raw`
import os,sys,json,re,hashlib,pathlib,tempfile,subprocess,fcntl,shutil,uuid,ipaddress

def digest(value): return hashlib.sha256(value).hexdigest()
def run(argv):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
    if p.returncode: raise RuntimeError('Command failed: '+pathlib.Path(argv[0]).name+' '+argv[1]+'; output withheld because Caddy diagnostics may contain secrets')
    return p.stdout.decode().strip()

def transaction(p):
    path=pathlib.Path(p['configPath'])
    if not path.is_absolute() or path.name!='Caddyfile' or path.is_symlink() or not path.is_file():
        raise RuntimeError('Expected a regular absolute Caddyfile path')
    if p['action'] not in ('inspect','plan','apply'): raise RuntimeError('Invalid action')
    lockpath=path.parent/'.swamp-caddy.lock'
    fd=os.open(str(lockpath),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        original=path.read_bytes(); before=digest(original)
        if len(original)>1048576: raise RuntimeError('Caddyfile exceeds 1 MiB limit')
        active=run([p['systemctlBinary'],'is-active','caddy'])=='active'
        result={'requestId':p['requestId'],'action':p['action'],'beforeSha256':before,
                'afterSha256':before,'changed':False,'validated':False,'serviceActive':active,
                'backupPath':None,'route':None}
        if p['action']=='inspect': return result
        if not active: raise RuntimeError('Caddy must already be active')
        if p.get('expectedSha256')!=before: raise RuntimeError('Caddyfile changed since inspection; inspect and plan again')
        name=p['name']; host=p['hostname']; zone=p['wildcardDomain']; upstream=p['upstream']
        dns=r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+'
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,31}',name): raise RuntimeError('Invalid route name')
        if not re.fullmatch(dns,host) or not re.fullmatch(dns,zone) or host.count('.')!=zone.count('.')+1 or not host.endswith('.'+zone): raise RuntimeError('Host must be one label beneath wildcard domain')
        if not re.fullmatch(r'(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}',upstream) or not 0<int(upstream.rsplit(':',1)[1])<65536: raise RuntimeError('Upstream must be host:port without credentials or directives')
        networks=[str(ipaddress.ip_network(c,strict=True)) for c in p['allowedCidrs']]
        if not networks or any(ipaddress.ip_network(c).prefixlen==0 for c in networks): raise RuntimeError('Explicit non-universal client networks required')
        begin='    # BEGIN swamp-caddy '+name
        end='    # END swamp-caddy '+name
        text=original.decode('utf-8')
        if '\r' in text: raise RuntimeError('Normalize CRLF manually before managing routes')
        if re.search(r'^\s*import\s',text,re.M): raise RuntimeError('Imported configuration needs an import-aware transaction; refusing to validate a partial configuration')
        if text.count(begin)!=text.count(end) or text.count(begin)>1: raise RuntimeError('Malformed managed markers')
        if begin in text:
            start=text.index(begin); stop=text.index(end)+len(end)
            if stop<start: raise RuntimeError('Reversed managed markers')
            if text[stop:stop+1]=='\n': stop+=1
            text=text[:start]+text[stop:]
        if re.search(r'(?<![a-zA-Z0-9_.-])'+re.escape(host)+r'(?![a-zA-Z0-9_.-])',text): raise RuntimeError('Host already occurs outside this managed route')
        anchor=re.compile(r'^\*\.'+re.escape(zone)+r'\s*\{[ \t]*$',re.M)
        matches=list(anchor.finditer(text))
        if len(matches)!=1: raise RuntimeError('Expected exactly one plain wildcard site header; inspect layout before adapting')
        block='\n'.join([begin,'    @swamp_'+name+' host '+host,'    handle @swamp_'+name+' {',
            '        @outside_'+name+' not remote_ip '+' '.join(networks),
            '        respond @outside_'+name+' "Forbidden" 403',
            '        reverse_proxy '+upstream,'    }',end])+'\n'
        insert=matches[0].end()+1
        if text[matches[0].end():insert]!='\n': raise RuntimeError('Wildcard header needs a newline')
        candidate=(text[:insert]+block+text[insert:]).encode()
        result.update(afterSha256=digest(candidate),changed=candidate!=original,route=block)
        meta=path.stat()
        with tempfile.TemporaryDirectory(prefix='.swamp-caddy-',dir=path.parent) as temp:
            staged=pathlib.Path(temp)/'Caddyfile'; staged.write_bytes(candidate); staged.chmod(0o600)
            # Validation requires real module provisioning, not only adaptation.
            run([p['caddyBinary'],'validate','--config',str(staged),'--adapter','caddyfile'])
            result['validated']=True
            if p['action']=='plan': return result
            if not result['changed']:
                # Reconcile a previous interrupted disk replacement, even when
                # desired bytes already match. This never restarts the service.
                run([p['systemctlBinary'],'reload','caddy'])
                if run([p['systemctlBinary'],'is-active','caddy'])!='active': raise RuntimeError('Caddy inactive after reload')
                return result
            if path.is_symlink() or digest(path.read_bytes())!=before: raise RuntimeError('Concurrent configuration edit; refusing apply')
            backups=path.parent/'.swamp-caddy-backups'
            if backups.is_symlink(): raise RuntimeError('Backup directory must not be a symlink')
            backups.mkdir(mode=0o700,exist_ok=True)
            if backups.stat().st_mode & 0o077: raise RuntimeError('Backup directory must be private')
            backup=backups/(before+'-'+uuid.uuid4().hex+'.Caddyfile')
            with open(backup,'xb') as f:
                os.chmod(backup,0o600); f.write(original); f.flush(); os.fsync(f.fileno())
            if digest(backup.read_bytes())!=before: raise RuntimeError('Backup verification failed')
            result['backupPath']=str(backup)
            os.chown(staged,meta.st_uid,meta.st_gid); os.chmod(staged,meta.st_mode & 0o777)
            with open(staged,'rb') as f: os.fsync(f.fileno())
            os.replace(staged,path)
            try:
                run([p['systemctlBinary'],'reload','caddy'])
                if run([p['systemctlBinary'],'is-active','caddy'])!='active': raise RuntimeError('Caddy inactive after reload')
                if digest(path.read_bytes())!=result['afterSha256']: raise RuntimeError('Caddyfile changed after reload')
            except Exception as error:
                if digest(path.read_bytes())!=result['afterSha256']: raise RuntimeError('Apply failed and concurrent edit prevents rollback; preserved backup: '+str(backup)) from error
                staged.write_bytes(original); os.chown(staged,meta.st_uid,meta.st_gid); staged.chmod(meta.st_mode & 0o777)
                os.replace(staged,path)
                try:
                    run([p['systemctlBinary'],'reload','caddy'])
                    if run([p['systemctlBinary'],'is-active','caddy'])!='active': raise RuntimeError('Inactive')
                except Exception as rollback_error: raise RuntimeError('Original Caddyfile restored but reload failed; backup: '+str(backup)) from rollback_error
                raise RuntimeError('Apply failed; original Caddyfile restored and reloaded') from error
        return result
`;
