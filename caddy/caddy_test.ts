import { driver } from "./driver.ts";

Deno.test("Caddy transaction preserves routes, blocks drift and rolls back failed reloads", async () => {
  const tests = String.raw`
import unittest
class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name); self.path=self.root/'Caddyfile'
        self.original=b'*.example.com {\n    tls {\n        dns cloudflare PRIVATE_TEST_SENTINEL\n    }\n    @existing host old.example.com\n    handle @existing {\n        reverse_proxy 192.0.2.10:8000\n    }\n}\n'
        self.path.write_bytes(self.original); self.path.chmod(0o640)
        self.caddy=self.root/'caddy'; self.systemctl=self.root/'systemctl'
        self.caddy.write_text('#!/usr/bin/env python3\nimport sys,pathlib\np=pathlib.Path(__file__).parent\nsys.exit(1 if (p/"invalid").exists() else 0)\n'); self.caddy.chmod(0o700)
        self.systemctl.write_text('#!/usr/bin/env python3\nimport sys,pathlib\np=pathlib.Path(__file__).parent\nif sys.argv[1]=="is-active": print("active")\nelse:\n f=p/"fail"\n if f.exists():\n  f.unlink();sys.exit(1)\n'); self.systemctl.chmod(0o700)
        self.p=dict(action='plan',requestId='test',configPath=str(self.path),caddyBinary=str(self.caddy),systemctlBinary=str(self.systemctl),name='notes',hostname='notes.example.com',wildcardDomain='example.com',upstream='192.0.2.20:8000',allowedCidrs=['192.0.2.0/24'],expectedSha256=digest(self.original))
    def test_plan(self):
        r=transaction(self.p); self.assertTrue(r['validated']); self.assertEqual(self.path.read_bytes(),self.original)
        self.assertNotIn('PRIVATE_TEST_SENTINEL',json.dumps(r)); self.assertIsNone(r['backupPath'])
    def test_apply_idempotent(self):
        self.p['action']='apply'; r=transaction(self.p); new=self.path.read_bytes()
        self.assertTrue(r['changed']); self.assertIn(b'@existing host old.example.com',new)
        backup=pathlib.Path(r['backupPath']); self.assertEqual(backup.read_bytes(),self.original)
        self.assertEqual(backup.stat().st_mode&0o777,0o600); self.assertEqual(self.path.stat().st_mode&0o777,0o640)
        self.p['expectedSha256']=digest(new); r=transaction(self.p); self.assertFalse(r['changed']); self.assertEqual(self.path.read_bytes(),new)
    def test_drift(self):
        self.path.write_bytes(self.original+b'# external edit\n')
        with self.assertRaisesRegex(RuntimeError,'changed since'): transaction(self.p)
        self.assertTrue(self.path.read_bytes().endswith(b'# external edit\n'))
    def test_validation_failure(self):
        (self.root/'invalid').touch(); self.p['action']='apply'
        with self.assertRaisesRegex(RuntimeError,'output withheld'): transaction(self.p)
        self.assertEqual(self.path.read_bytes(),self.original)
    def test_reload_rollback(self):
        (self.root/'fail').touch(); self.p['action']='apply'
        with self.assertRaisesRegex(RuntimeError,'restored and reloaded'): transaction(self.p)
        self.assertEqual(self.path.read_bytes(),self.original)
    def test_unmanaged_collision(self):
        self.p['hostname']='old.example.com'
        with self.assertRaisesRegex(RuntimeError,'outside this managed'): transaction(self.p)
    def test_import_refused(self):
        self.path.write_bytes(self.original+b'import other.conf\n'); self.p['expectedSha256']=digest(self.path.read_bytes())
        with self.assertRaisesRegex(RuntimeError,'Imported configuration'): transaction(self.p)
    def test_no_universal_network(self):
        for cidr in ['0.0.0.0/0','::/0','999.0.0.0/24','192.0.2.0/24\nrespond 200']:
            self.p['allowedCidrs']=[cidr]
            with self.assertRaises((RuntimeError,ValueError)): transaction(self.p)
    def test_injection(self):
        for field,value in [('name','x\n}'),('hostname','notes.example.com\n}'),('upstream','192.0.2.20:80\nrespond 200'),('wildcardDomain','example.com.*')]:
            p=dict(self.p);p[field]=value
            with self.assertRaises(RuntimeError):transaction(p)
    def test_symlink(self):
        self.path.rename(self.root/'original'); self.path.symlink_to(self.root/'original')
        with self.assertRaisesRegex(RuntimeError,'regular absolute'): transaction(self.p)
    def test_duplicate_anchor(self):
        self.path.write_bytes(self.original+self.original); self.p['expectedSha256']=digest(self.path.read_bytes())
        with self.assertRaisesRegex(RuntimeError,'exactly one'): transaction(self.p)
    def test_inspect(self):
        self.p['action']='inspect';r=transaction(self.p)
        self.assertEqual(r['beforeSha256'],digest(self.original));self.assertTrue(r['serviceActive']);self.assertIsNone(r['route'])
unittest.main(argv=['test'],verbosity=2)
`;
  const output = await new Deno.Command("python3", {
    args: ["-c", driver + tests],
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!output.success) throw new Error(new TextDecoder().decode(output.stderr));
  console.log(new TextDecoder().decode(output.stderr));
});
