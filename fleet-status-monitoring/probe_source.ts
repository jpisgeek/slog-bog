/** Optional fixed Python 3 source for restricted SSH probes; the local starter does not execute it. */
export const probeScript = String
  .raw`"""Read-only OS and root-volume counters. No network, user files or elevation."""
import datetime,json,os,platform,subprocess,time

def command(argv):
 try:return subprocess.check_output(argv,stderr=subprocess.DEVNULL,timeout=3,text=True).strip()
 except Exception:return None

def integer(value):
 try:return max(0,int(value))
 except (ValueError,TypeError):return None

family={'Darwin':'macos','Linux':'linux','Windows':'windows'}.get(platform.system(),'other')
r={'schemaVersion':1,
 'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00',
 'Z'),
 'family':family,
 'osName':platform.system(),
 'osVersion':None,
 'kernel':platform.release(),
 'architecture':platform.machine(),
 'logicalCores':os.cpu_count(),
 'uptimeSeconds':None,
 'memoryTotalBytes':None,
 'memoryAvailableBytes':None,
 'memoryAvailableKind':'unavailable',
 'diskTotalBytes':None,
 'diskAvailableBytes':None,
 'load1':None}
try:r['load1']=os.getloadavg()[0]
except (AttributeError,OSError):pass
try:
 # Observe only the startup data filesystem, never enumerate mounted images.
 volume='/System/Volumes/Data' if family=='macos' and os.path.isdir('/System/Volumes/Data') else '/'
 s=os.statvfs(volume);r['diskTotalBytes']=s.f_blocks*s.f_frsize;r['diskAvailableBytes']=s.f_bavail*s.f_frsize
except (AttributeError,OSError):pass
if family=='macos':
 r['osName']='macOS';r['osVersion']=command(['/usr/bin/sw_vers','-productVersion']) or None
 r['memoryTotalBytes']=integer(command(['/usr/sbin/sysctl','-n','hw.memsize']))
 boot=command(['/usr/sbin/sysctl','-n','kern.boottime'])
 if boot:
  import re
  m=re.search(r'sec = (\d+)',boot)
  if m:r['uptimeSeconds']=max(0,time.time()-int(m[1]))
 vm=command(['/usr/bin/vm_stat'])
 if vm:
  import re
  page=re.search(r'page size of (\d+) bytes',vm)
  counts=[re.search(r'^'+re.escape(k)+r':\s+(\d+)',vm,re.M) for k in ['Pages free','Pages inactive','Pages speculative']]
  if page and all(counts):
   r['memoryAvailableBytes']=int(page[1])*sum(int(m[1]) for m in counts)
   r['memoryAvailableKind']='free+inactive+speculative estimate'
elif family=='linux':
 try:
  with open('/etc/os-release') as f:
   pairs=dict(line.rstrip().split('=',1) for line in f if '=' in line)
  r['osName']=pairs.get('NAME','Linux').strip('"');r['osVersion']=(pairs.get('VERSION_ID') or '').strip('"').strip() or None
 except OSError:pass
 try:
  with open('/proc/meminfo') as f:mem={k:integer(v.strip().split()[0]) for k,v in (line.split(':',1) for line in f)}
  r['memoryTotalBytes']=mem['MemTotal']*1024
  if mem.get('MemAvailable') is not None:r['memoryAvailableBytes']=mem['MemAvailable']*1024;r['memoryAvailableKind']='MemAvailable'
 except (OSError,KeyError,TypeError):pass
 try:
  with open('/proc/uptime') as f:r['uptimeSeconds']=float(f.read(80).split()[0])
 except (OSError,ValueError):pass
print(json.dumps(r,allow_nan=False,separators=(',',':')))
`;
