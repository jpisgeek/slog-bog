"""Probe fixtures: measurements must use the real startup filesystem only."""
import contextlib,io,json,runpy,types,unittest
from pathlib import Path
from unittest.mock import patch

class ProbeTests(unittest.TestCase):
 def test_macos_observes_data_volume_and_never_enumerates_disk_images(self):
  paths=[]
  def statvfs(path):
   paths.append(path)
   self.assertEqual(path,'/System/Volumes/Data')
   return types.SimpleNamespace(f_blocks=1000,f_frsize=4096,f_bavail=500)
  def command(argv,**_):
   return {('/usr/bin/sw_vers','-productVersion'):'test-os',('/usr/sbin/sysctl','-n','hw.memsize'):'16384',('/usr/sbin/sysctl','-n','kern.boottime'):'{ sec = 100, usec = 0 }',('/usr/bin/vm_stat',):'Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1.\nPages inactive: 1.\nPages speculative: 1.'}[tuple(argv)]
  output=io.StringIO()
  with patch('platform.system',return_value='Darwin'),patch('platform.release',return_value='test-kernel'),patch('platform.machine',return_value='arm64'),patch('os.path.isdir',return_value=True),patch('os.statvfs',side_effect=statvfs),patch('os.listdir',side_effect=AssertionError('No mount scan')),patch('subprocess.check_output',side_effect=command),contextlib.redirect_stdout(output):
   runpy.run_path(str(Path(__file__).with_name('probe.py')))
  result=json.loads(output.getvalue());self.assertEqual(paths,['/System/Volumes/Data']);self.assertEqual(result['diskAvailableBytes'],2048000);self.assertEqual(result['memoryAvailableBytes'],12288);self.assertEqual(result['osVersion'],'test-os')

 def test_linux_uses_memavailable_and_root_without_sourcing_os_release(self):
  files={'/etc/os-release':'NAME="Example Linux"\nVERSION_ID="test-version"\n','/proc/meminfo':'MemTotal: 1000 kB\nMemAvailable: 250 kB\nMemFree: 20 kB\n','/proc/uptime':'123.5 444.0\n'}
  def opened(path,*_args,**_kwargs):return io.StringIO(files[path])
  output=io.StringIO();volume=types.SimpleNamespace(f_blocks=1000,f_frsize=4096,f_bavail=250)
  with patch('platform.system',return_value='Linux'),patch('platform.release',return_value='test-kernel'),patch('platform.machine',return_value='x86_64'),patch('os.statvfs',return_value=volume) as stat,patch('builtins.open',side_effect=opened),patch('subprocess.check_output',side_effect=AssertionError('No shell command needed')),contextlib.redirect_stdout(output):
   runpy.run_path(str(Path(__file__).with_name('probe.py')))
  result=json.loads(output.getvalue());stat.assert_called_once_with('/');self.assertEqual(result['memoryAvailableBytes'],256000);self.assertEqual(result['memoryAvailableKind'],'MemAvailable');self.assertEqual(result['uptimeSeconds'],123.5);self.assertEqual(result['osName'],'Example Linux')
 def test_macos_missing_product_version_does_not_claim_kernel_as_os_version(self):
  output=io.StringIO();volume=types.SimpleNamespace(f_blocks=1000,f_frsize=4096,f_bavail=250)
  with patch('platform.system',return_value='Darwin'),patch('platform.release',return_value='test-kernel'),patch('os.path.isdir',return_value=True),patch('os.statvfs',return_value=volume),patch('subprocess.check_output',side_effect=OSError('Metadata unavailable')),contextlib.redirect_stdout(output):
   runpy.run_path(str(Path(__file__).with_name('probe.py')))
  result=json.loads(output.getvalue());self.assertIsNone(result['osVersion']);self.assertEqual(result['kernel'],'test-kernel')

 def test_linux_missing_distribution_version_does_not_claim_kernel_as_os_version(self):
  for release in [None,'NAME="Example Linux"\n','NAME="Example Linux"\nVERSION_ID=""\n']:
   with self.subTest(release=release):
    def opened(path,*_args,**_kwargs):
     if path=='/etc/os-release' and release is not None:return io.StringIO(release)
     raise OSError('Metadata unavailable')
    output=io.StringIO();volume=types.SimpleNamespace(f_blocks=1000,f_frsize=4096,f_bavail=250)
    with patch('platform.system',return_value='Linux'),patch('platform.release',return_value='test-kernel'),patch('os.statvfs',return_value=volume),patch('builtins.open',side_effect=opened),contextlib.redirect_stdout(output):
     runpy.run_path(str(Path(__file__).with_name('probe.py')))
    result=json.loads(output.getvalue());self.assertIsNone(result['osVersion']);self.assertEqual(result['kernel'],'test-kernel')

if __name__=='__main__':unittest.main()
