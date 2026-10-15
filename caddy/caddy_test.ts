import { driver } from "./driver.ts";
import {
  helperDigest,
  helperSource,
  model,
  Removal,
  Route,
  wrapperScript,
} from "./caddy.ts";
import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import fc from "npm:fast-check@4.8.0";

Deno.test("Caddy transaction preserves routes, blocks drift and rolls back failed reloads", async () => {
  const tests = String.raw`
import unittest
from unittest.mock import patch
from types import SimpleNamespace
class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=os.getcwd()); self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name); self.path=self.root/'Caddyfile'
        self.original=b'*.example.com {\n    tls {\n        dns cloudflare PRIVATE_TEST_SENTINEL\n    }\n    @existing host old.example.com\n    handle @existing {\n        reverse_proxy 192.0.2.10:8000\n    }\n}\n'
        self.path.write_bytes(self.original); self.path.chmod(0o640)
        self.caddy=self.root/'caddy'; self.systemctl=self.root/'systemctl'
        self.caddy.write_text('#!/usr/bin/env python3\nimport sys,pathlib\np=pathlib.Path(__file__).parent\nsys.exit(1 if (p/"invalid").exists() else 0)\n'); self.caddy.chmod(0o700)
        self.systemctl.write_text('#!/usr/bin/env python3\nimport sys,pathlib\np=pathlib.Path(__file__).parent\nif sys.argv[1]=="is-active": print("active")\nelse:\n f=p/"fail"\n if f.exists():\n  f.unlink();sys.exit(1)\n'); self.systemctl.chmod(0o700)
        self.p=dict(action='plan',requestId='test',configPath=str(self.path),caddyBinary=str(self.caddy),systemctlBinary=str(self.systemctl),name='notes',hostname='notes.example.com',wildcardDomain='example.com',upstream='192.0.2.20:8000',upstreamScheme='http',allowedCidrs=['192.0.2.0/24'],expectedSha256=digest(self.original))
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
        for cidr in ['0.0.0.0/0','::/0','999.0.0.0/24','192.0.2.0/24\nrespond 200',True,1,None,{}]:
            self.p['allowedCidrs']=[cidr]
            with self.assertRaises((RuntimeError,ValueError)): transaction(self.p)
        for networks in [['0.0.0.0/1','128.0.0.0/1'],['::/1','8000::/1'],
                         ['0.0.0.0/1','128.0.0.0/2','192.0.0.0/2'],
                         ['192.0.2.0/24','8000::/1','::/1']]:
            self.p['allowedCidrs']=networks
            with self.assertRaisesRegex(RuntimeError,'non-universal'): transaction(self.p)
        # Overlap/duplicates are not additional address coverage; a gap remains.
        self.p['allowedCidrs']=['0.0.0.0/1','0.0.0.0/2','0.0.0.0/1','192.0.2.0/24']
        self.assertTrue(transaction(self.p)['validated'])
    def test_concurrent_content_or_metadata_change_during_validation(self):
        self.p['action']='apply'
        for change in ['p.write_bytes(p.read_bytes()+b"# changed")','p.chmod(0o600)']:
            self.path.write_bytes(self.original);self.path.chmod(0o640)
            self.caddy.write_text('#!/usr/bin/env python3\nimport pathlib\np=pathlib.Path(__file__).parent/"Caddyfile"\n'+change+'\n')
            with self.assertRaisesRegex(RuntimeError,'Concurrent configuration'):transaction(self.p)
            self.assertFalse((self.root/'.swamp-caddy-backups').exists())
            if 'chmod' in change:self.assertEqual(self.path.stat().st_mode&0o777,0o600)
            else:self.assertEqual(self.path.read_bytes(),self.original+b'# changed')
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
    def test_https_plan_and_rollback(self):
        self.p.update(upstream='192.0.2.20:8443',upstreamScheme='https',upstreamCaFile='/etc/caddy/trust/example-root-ca.pem')
        with patch.dict(globals(),validate_ca_file=lambda p:p):
            r=transaction(self.p)
            self.assertIn('reverse_proxy https://192.0.2.20:8443 {',r['route'])
            self.assertIn('tls_trust_pool file /etc/caddy/trust/example-root-ca.pem',r['route'])
            self.assertIn('not remote_ip 192.0.2.0/24',r['route'])
            self.assertNotIn('insecure',r['route']);self.assertEqual(self.path.read_bytes(),self.original)
            (self.root/'fail').touch(); self.p['action']='apply'
            with self.assertRaisesRegex(RuntimeError,'restored and reloaded'): transaction(self.p)
            self.assertEqual(self.path.read_bytes(),self.original)
    def test_https_requires_scoped_ca(self):
        for ca in [None,'/tmp/ca.pem','/etc/caddy/trust/../ca.pem','/etc/caddy/trust/a.pem\nrespond 200']:
            p=dict(self.p,upstreamScheme='https',upstreamCaFile=ca)
            with self.assertRaisesRegex(RuntimeError,'CA file must'): transaction(p)
        with self.assertRaisesRegex(RuntimeError,'Invalid upstream scheme'): transaction(dict(self.p,upstreamScheme='ftp'))
        with self.assertRaisesRegex(RuntimeError,'HTTP upstream must'): transaction(dict(self.p,upstreamCaFile='/etc/caddy/trust/ca.pem'))
    def test_ca_permissions_and_public_only(self):
        from unittest.mock import MagicMock
        ca=MagicMock();ca.parent=MagicMock()
        ca.is_symlink.return_value=False;ca.parent.is_symlink.return_value=False
        ca.is_file.return_value=True
        ca.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o100644,st_size=100)
        ca.parent.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o40755)
        ca.read_text.return_value='-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'
        with patch.object(pathlib,'Path',return_value=ca):
            self.assertEqual(validate_ca_file('/etc/caddy/trust/ca.pem'),'/etc/caddy/trust/ca.pem')
            ca.is_symlink.return_value=True
            with self.assertRaisesRegex(RuntimeError,'symlinks'):validate_ca_file('/etc/caddy/trust/ca.pem')
            ca.is_symlink.return_value=False
            ca.stat.return_value=SimpleNamespace(st_uid=1000,st_mode=0o100644,st_size=100)
            with self.assertRaisesRegex(RuntimeError,'root-owned'):validate_ca_file('/etc/caddy/trust/ca.pem')
            ca.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o100666,st_size=100)
            with self.assertRaisesRegex(RuntimeError,'root-owned'):validate_ca_file('/etc/caddy/trust/ca.pem')
            ca.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o100644,st_size=100)
            ca.read_text.return_value='-----BEGIN PRIVATE KEY-----'
            with self.assertRaisesRegex(RuntimeError,'public certificates'):validate_ca_file('/etc/caddy/trust/ca.pem')
    def test_remove_exact_managed_route(self):
        self.p['action']='apply';transaction(self.p);installed=self.path.read_bytes()
        p={k:self.p[k] for k in ['requestId','configPath','caddyBinary','systemctlBinary','name','hostname','wildcardDomain']}
        p.update(action='remove',expectedSha256=digest(installed))
        r=transaction(p)
        self.assertTrue(r['changed']);self.assertTrue(r['validated']);self.assertIsNone(r['route'])
        self.assertEqual(self.path.read_bytes(),self.original)
        self.assertEqual(pathlib.Path(r['backupPath']).read_bytes(),installed)
    def test_remove_absent_is_idempotent(self):
        p={k:self.p[k] for k in ['requestId','configPath','caddyBinary','systemctlBinary','name','hostname','wildcardDomain','expectedSha256']}
        p['action']='remove';r=transaction(p)
        self.assertFalse(r['changed']);self.assertTrue(r['validated']);self.assertEqual(self.path.read_bytes(),self.original)
    def test_remove_refuses_identity_mismatch(self):
        self.p['action']='apply';transaction(self.p);installed=self.path.read_bytes()
        p={k:self.p[k] for k in ['requestId','configPath','caddyBinary','systemctlBinary','name','wildcardDomain']}
        p.update(action='remove',hostname='other.example.com',expectedSha256=digest(installed))
        with self.assertRaisesRegex(RuntimeError,'identity differs'):transaction(p)
        self.assertEqual(self.path.read_bytes(),installed)
    def test_inspect(self):
        self.p['action']='inspect';r=transaction(self.p)
        self.assertEqual(r['beforeSha256'],digest(self.original));self.assertTrue(r['serviceActive']);self.assertIsNone(r['route'])
    def test_inactive_inspection_is_observation_not_transport_failure(self):
        self.systemctl.write_text('#!/usr/bin/env python3\nimport sys\nprint("inactive");sys.exit(3)\n')
        self.p['action']='inspect';r=transaction(self.p)
        self.assertFalse(r['serviceActive']);self.assertEqual(r['beforeSha256'],digest(self.original))
        self.p['action']='apply'
        with self.assertRaisesRegex(RuntimeError,'already be active'):transaction(self.p)
        self.assertEqual(self.path.read_bytes(),self.original)
    def test_marker_suffix_does_not_authorize_removal(self):
        self.p['action']='apply';transaction(self.p)
        installed=self.path.read_bytes().replace(b'swamp-caddy notes',b'swamp-caddy notes_suffix')
        self.path.write_bytes(installed)
        self.p.update(action='remove',expectedSha256=digest(installed))
        with self.assertRaisesRegex(RuntimeError,'markers'):transaction(self.p)
        self.assertEqual(self.path.read_bytes(),installed)
    def test_unmanaged_host_case_and_terminal_dot_are_equivalent(self):
        for host in [b'NOTES.EXAMPLE.COM',b'notes.example.com.',b'NOTES.EXAMPLE.COM.']:
            original=self.original.replace(b'old.example.com',host)
            self.path.write_bytes(original);self.p['expectedSha256']=digest(original)
            with self.assertRaisesRegex(RuntimeError,'outside this managed'):transaction(self.p)
            self.assertEqual(self.path.read_bytes(),original)
    def test_unsafe_paths_do_not_mutate(self):
        for path in [self.root,self.path,self.caddy,self.systemctl]:
            mode=path.stat().st_mode&0o777;path.chmod(mode|0o022)
            with self.assertRaisesRegex(RuntimeError,'not writable'):transaction(self.p)
            path.chmod(mode);self.assertEqual(self.path.read_bytes(),self.original)
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'symlinks'):transaction(dict(self.p,configPath=str(alias/'Caddyfile')))
        with self.assertRaisesRegex(RuntimeError,'canonical'):transaction(dict(self.p,configPath=str(self.root)+'/../'+self.root.name+'/Caddyfile'))
    def test_backups_are_bounded_and_foreign_entries_survive(self):
        self.p['action']='apply';r=transaction(self.p);backups=pathlib.Path(r['backupPath']).parent
        foreign=backups/'operator-notes';foreign.write_bytes(b'keep');foreign.chmod(0o600)
        link=backups/('b'*64+'-'+'c'*32+'.Caddyfile');link.symlink_to(foreign)
        for i in range(7):
            current=self.path.read_bytes();self.p.update(expectedSha256=digest(current),upstream='192.0.2.20:'+str(8100+i))
            r=transaction(self.p)
        owned=[p for p in backups.iterdir() if p.is_file() and not p.is_symlink() and re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}\.Caddyfile',p.name)]
        self.assertEqual(len(owned),5);self.assertIn(pathlib.Path(r['backupPath']),owned)
        self.assertEqual(foreign.read_bytes(),b'keep');self.assertTrue(link.is_symlink())
        for i in range(7):
            self.p.update(expectedSha256=digest(self.path.read_bytes()),upstream='192.0.2.20:'+str(8200+i))
            (self.root/'fail').touch()
            with self.assertRaisesRegex(RuntimeError,'restored and reloaded'):transaction(self.p)
        owned=[p for p in backups.iterdir() if p.is_file() and not p.is_symlink() and re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}\.Caddyfile',p.name)]
        self.assertEqual(len(owned),5);self.assertEqual(foreign.read_bytes(),b'keep')
    def test_command_output_and_time_are_bounded(self):
        self.caddy.write_text('#!/usr/bin/env python3\nimport os\nos.write(1,b"x"*1000000)\n');self.caddy.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,'output limit'):transaction(self.p)
        self.assertEqual(self.path.read_bytes(),self.original)
        self.caddy.write_text('#!/usr/bin/env python3\nimport os\nos.write(2,b"PRIVATE_TEST_SENTINEL"*100000)\n');self.caddy.chmod(0o700)
        self.assertTrue(transaction(self.p)['validated'])
        start=time.monotonic()
        with self.assertRaisesRegex(RuntimeError,'deadline'):bounded_process([sys.executable,'-c','import time;time.sleep(30)'],timeout=0.15)
        self.assertLess(time.monotonic()-start,2)
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

Deno.test("the committed helper is exactly the transaction plus its entry point", async () => {
  const onDisk = await Deno.readTextFile(
    new URL("./swamp-caddy.py", import.meta.url),
  );
  assertEquals(onDisk, helperSource);
  assertEquals((await helperDigest()).length, 64);
});

Deno.test("the helper refuses to run unprivileged and refuses caller-supplied paths", async () => {
  const run = async (payload: string) => {
    const p = await new Deno.Command("python3", {
      args: ["-c", helperSource],
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const w = p.stdin.getWriter();
    await w.write(new TextEncoder().encode(payload));
    await w.close();
    const out = await p.output();
    return { code: out.code, text: new TextDecoder().decode(out.stdout) };
  };
  // Not root here, so every call must stop at the root check before reading anything.
  const r = await run(JSON.stringify({ action: "inspect", requestId: "abc" }));
  assertEquals(r.code, 3);
  assertStringIncludes(r.text, "must run as root");
});

Deno.test("the wrapper never elevates itself and pins the helper digest", () => {
  const s = wrapperScript("/usr/local/sbin/swamp-caddy", "a".repeat(64), {
    action: "inspect",
    requestId: "x",
  });
  assertStringIncludes(s, "['/usr/bin/sudo','-n',helper]");
  assertStringIncludes(s, '"a'.slice(0, 1) + "a".repeat(64));
  assertStringIncludes(s, "not a pinned compatible version");
  assertEquals(s.includes("sudo=true"), false);
});

Deno.test("inspect accepts only correlated current-invocation SSH evidence", async () => {
  const requestId = "00000000-0000-4000-8000-000000000001";
  const modelId = "00000000-0000-4000-8000-000000000002";
  const target = {
    definition: { id: modelId, name: "YOUR_SSH_MODEL" },
    type: { normalized: "@swamp/ssh" },
  };
  const result = {
    requestId,
    action: "inspect",
    beforeSha256: "a".repeat(64),
    afterSha256: "a".repeat(64),
    changed: false,
    validated: false,
    serviceActive: false,
    backupPath: null,
    route: null,
  };
  const resource = {
    kind: "resource",
    specName: "runResult",
    name: "run-script-YOUR_HOST",
    version: 7,
    size: 1200,
    metadata: {
      ownerDefinition: { ownerType: "model-method", ownerRef: modelId },
    },
    attributes: {
      host: "YOUR_HOST",
      method: "script",
      exitCode: 0,
      signal: null,
      stdout: JSON.stringify(result),
    },
  };
  const writes: Record<string, unknown>[] = [];
  const ctx: Parameters<typeof model.methods.inspect.execute>[1] = {
    globalArgs: { sshModel: "YOUR_SSH_MODEL", host: "YOUR_HOST" },
    signal: new AbortController().signal,
    logger: { info: () => {} },
    definitionRepository: {
      findByNameGlobal: (name) =>
        Promise.resolve(name === "YOUR_SSH_MODEL" ? target : null),
      findAllByIdGlobal: () => Promise.resolve([target]),
    },
    runModel: (request) => {
      // This synthetic provider only serves the configured exact host and ID.
      if (
        request.definition !== modelId || request.method !== "script" ||
        request.arguments.hosts !== "name:YOUR_HOST" ||
        request.arguments.sudo !== false ||
        JSON.stringify(request.arguments.okExitCodes) !== "[0]"
      ) throw new Error("Wrong transport capability");
      return Promise.resolve({ ok: true, resources: [resource] });
    },
    writeResource: (_spec, _name, value) => {
      writes.push(value);
      return Promise.resolve({ name: "fixture-operation" });
    },
  };
  const originalRandomUUID = crypto.randomUUID;
  crypto.randomUUID = () => requestId;
  try {
    await model.methods.inspect.execute({}, ctx);
    assertEquals(writes, [{
      ...result,
      transport: {
        modelId,
        host: "YOUR_HOST",
        name: "run-script-YOUR_HOST",
        version: 7,
      },
    }]);
    writes.length = 0;
    const invalidResources = [
      { ...resource, name: "run-script-OTHER_HOST" },
      { ...resource, specName: "other" },
      { ...resource, kind: "file" },
      { ...resource, version: 0 },
      { ...resource, size: 131073 },
      {
        ...resource,
        metadata: {
          ownerDefinition: {
            ownerType: "model-method",
            ownerRef: requestId,
          },
        },
      },
      {
        ...resource,
        attributes: { ...resource.attributes, host: "OTHER_HOST" },
      },
      { ...resource, attributes: { ...resource.attributes, method: "exec" } },
      { ...resource, attributes: { ...resource.attributes, exitCode: 1 } },
      {
        ...resource,
        attributes: { ...resource.attributes, signal: "SIGTERM" },
      },
      {
        ...resource,
        attributes: { ...resource.attributes, error: "PRIVATE_TEST_SENTINEL" },
      },
      {
        ...resource,
        attributes: { ...resource.attributes, stdout: "x".repeat(16385) },
      },
    ];
    for (const invalid of invalidResources) {
      await assertRejects(
        () =>
          model.methods.inspect.execute({}, {
            ...ctx,
            runModel: () => Promise.resolve({ ok: true, resources: [invalid] }),
          }),
        Error,
        "invalid or mismatched",
      );
    }
    for (
      const stdout of [
        "not JSON",
        JSON.stringify({ ...result, requestId: modelId }),
        JSON.stringify({ ...result, action: "apply" }),
        JSON.stringify({ ...result, route: "PRIVATE_TEST_SENTINEL" }),
        JSON.stringify({ ...result, backupPath: "/tmp/PRIVATE_TEST_SENTINEL" }),
        JSON.stringify({ ...result, changed: true }),
        JSON.stringify({ ...result, validated: true }),
        JSON.stringify({ ...result, afterSha256: "b".repeat(64) }),
        JSON.stringify({ ...result, PRIVATE_TEST_SENTINEL: "unexpected" }),
        JSON.stringify(result).slice(0, -1) + ',"__proto__":{}}',
        JSON.stringify({ error: "PRIVATE_TEST_SENTINEL" }),
      ]
    ) {
      const error = await assertRejects(() =>
        model.methods.inspect.execute({}, {
          ...ctx,
          runModel: () =>
            Promise.resolve({
              ok: true,
              resources: [{
                ...resource,
                attributes: { ...resource.attributes, stdout },
              }],
            }),
        })
      );
      assertEquals(String(error).includes("PRIVATE_TEST_SENTINEL"), false);
    }
    for (const resources of [[], [resource, resource]]) {
      await assertRejects(() =>
        model.methods.inspect.execute({}, {
          ...ctx,
          runModel: () => Promise.resolve({ ok: true, resources }),
        })
      );
    }
    const failed = await assertRejects(() =>
      model.methods.inspect.execute({}, {
        ...ctx,
        runModel: () =>
          Promise.resolve({
            ok: false,
            error: { message: "PRIVATE_TEST_SENTINEL" },
          }),
      })
    );
    assertEquals(String(failed).includes("PRIVATE_TEST_SENTINEL"), false);
    await assertRejects(() =>
      model.methods.inspect.execute({}, {
        ...ctx,
        definitionRepository: {
          findByNameGlobal: () =>
            Promise.resolve({
              ...target,
              definition: { ...target.definition, name: "UUID_SHADOW" },
            }),
          findAllByIdGlobal: () => Promise.resolve([target]),
        },
      })
    );
    await assertRejects(() =>
      model.methods.inspect.execute({ arbitrary: true }, ctx)
    );
    assertEquals(writes, []);
  } finally {
    crypto.randomUUID = originalRandomUUID;
  }
});

Deno.test("route schema defaults to verified HTTPS and requires explicit HTTP opt-in", () => {
  const base = {
    name: "proxy",
    hostname: "proxy.example.com",
    wildcardDomain: "example.com",
    upstream: "192.0.2.20:8443",
    allowedCidrs: ["192.0.2.0/24"],
    expectedSha256: "a".repeat(64),
  };
  assertEquals(Route.safeParse(base).success, false);
  assertEquals(
    Route.parse({ ...base, upstreamScheme: "http" }).upstreamScheme,
    "http",
  );
  assertEquals(
    Route.safeParse({ ...base, upstreamScheme: "https" }).success,
    false,
  );
  assertEquals(
    Route.safeParse({
      ...base,
      upstreamScheme: "https",
      upstreamCaFile: "/etc/caddy/trust/example-root-ca.pem",
    }).success,
    true,
  );
  assertEquals(
    Route.safeParse({
      ...base,
      upstreamScheme: "http",
      upstreamCaFile: "/etc/caddy/trust/example-root-ca.pem",
    }).success,
    false,
  );
  assertEquals(
    Route.safeParse({
      ...base,
      upstreamScheme: "https",
      upstreamCaFile: "/tmp/ca.pem",
    }).success,
    false,
  );
  assertEquals(
    Route.parse({
      ...base,
      upstreamCaFile: "/etc/caddy/trust/example-root-ca.pem",
    }).upstreamScheme,
    "https",
  );
  for (
    const extra of [
      { allowedCidrs: ["0.0.0.0/0"] },
      { allowedCidrs: ["::/0"] },
      { allowedCidrs: ["0.0.0.0/1", "128.0.0.0/1"] },
      { allowedCidrs: ["::/1", "8000::/1"] },
      { allowedCidrs: ["192.0.2.0/24", "8000::/1", "::/1"] },
      { allowedCidrs: ["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"] },
      { allowedCidrs: ["2001:db8::/129"] },
      { allowedCidrs: Array(33).fill("192.0.2.0/24") },
      { arbitrary: "unsupported" },
    ]
  ) {
    assertEquals(
      Route.safeParse({ ...base, upstreamScheme: "http", ...extra }).success,
      false,
    );
  }
  for (
    const allowedCidrs of [
      ["0.0.0.0/1", "0.0.0.0/2", "0.0.0.0/1", "192.0.2.0/24"],
      ["8000::/1", "::/2"],
      ["0.0.0.0/1", "::/1"],
    ]
  ) {
    assertEquals(
      Route.safeParse({ ...base, upstreamScheme: "http", allowedCidrs })
        .success,
      true,
    );
  }
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 4 }),
    fc.nat(),
    (prefix, holeSeed) => {
      // Equal-sized disjoint partitions independently define full coverage.
      // Removing any one leaves a real hole; overlap cannot fill that hole.
      const count = 2 ** prefix;
      for (const ipv6 of [false, true]) {
        const full = Array.from(
          { length: count },
          (_, i) =>
            ipv6
              ? (i * 65536 / count).toString(16) + "::/" + prefix
              : (i * 256 / count) + ".0.0.0/" + prefix,
        );
        const parse = (allowedCidrs: string[]) =>
          Route.safeParse({ ...base, upstreamScheme: "http", allowedCidrs })
            .success;
        assertEquals(parse(full.toReversed()), false);
        const partial = full.filter((_, i) => i !== holeSeed % count);
        assertEquals(parse([...partial, partial[0]]), true);
      }
    },
  ));
});

Deno.test("removal schema requires only exact route identity and digest", () => {
  const removal = {
    name: "retired",
    hostname: "retired.example.com",
    wildcardDomain: "example.com",
    expectedSha256: "a".repeat(64),
  };
  assertEquals(Removal.parse(removal), removal);
  assertEquals(
    Removal.safeParse({ ...removal, expectedSha256: "not-a-digest" }).success,
    false,
  );
});

Deno.test("unexpected route fields, including prototype keys, never become operational inputs", async () => {
  const valid = {
    name: "notes",
    hostname: "notes.example.com",
    wildcardDomain: "example.com",
    upstream: "backend.example.com:8000",
    upstreamScheme: "http",
    allowedCidrs: ["192.0.2.0/24"],
    expectedSha256: "a".repeat(64),
  };
  const context = {
    globalArgs: { sshModel: "YOUR_SSH_MODEL", host: "YOUR_HOST" },
    signal: new AbortController().signal,
    logger: { info: () => {} },
    writeResource: () => Promise.resolve({}),
  };
  await fc.assert(
    fc.asyncProperty(
      fc.oneof(
        fc.constantFrom("__proto__", "constructor", "prototype"),
        fc.string({ maxLength: 100 }).filter((key) =>
          !Object.hasOwn(valid, key)
        ),
      ),
      fc.jsonValue(),
      async (key, value) => {
        const input = { ...valid };
        Object.defineProperty(input, key, { value, enumerable: true });
        await assertRejects(
          () => model.methods.plan.execute(input, context),
          Error,
          "Caddy data contains unsupported fields or values; details withheld",
        );
      },
    ),
    { numRuns: 200 },
  );
});

Deno.test("helper export reports delivered bytes, not remote service health", async () => {
  let delivered = "";
  const records: { spec: string; value: Record<string, unknown> }[] = [];
  await model.methods.helper.execute({}, {
    globalArgs: {},
    signal: new AbortController().signal,
    logger: { info: () => {} },
    createFileWriter: () => ({
      writeText: (text) => {
        delivered = text;
        return Promise.resolve({ name: "helper" });
      },
    }),
    writeResource: (spec, _name, value) => {
      records.push({ spec, value });
      return Promise.resolve({ name: "helper-digest" });
    },
  });
  const bytes = new TextEncoder().encode(delivered);
  const sha256 = [
    ...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  ]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
  assertEquals(records, [{
    spec: "helperDigest",
    value: { sha256, bytes: bytes.length },
  }]);
  assertEquals(delivered.startsWith("#!/usr/bin/python3\n"), true);
});

Deno.test("plan, apply and removal agree with the transaction and reject forged response fields", async () => {
  const root = await Deno.makeTempDir({
    dir: decodeURIComponent(new URL(".", import.meta.url).pathname),
  });
  const modelId = "00000000-0000-4000-8000-000000000002";
  const target = {
    definition: { id: modelId, name: "YOUR_SSH_MODEL" },
    type: { normalized: "@swamp/ssh" },
  };
  const stored: Record<string, unknown>[] = [];
  let version = 0;
  let tamper: Record<string, unknown> | null = null;
  const fixture = String.raw`
import ast
request=json.load(sys.stdin);root=pathlib.Path(request['root']);path=root/'Caddyfile'
if not path.exists():
    path.write_text('*.example.com {\n    tls internal\n}\n');path.chmod(0o600)
for name,body in [('caddy',''),('systemctl','print("active")')]:
    binary=root/name;binary.write_text('#!/usr/bin/env python3\n'+body+'\n');binary.chmod(0o700)
# Inspect only a literal JSON payload; never execute the supplied wrapper.
tree=ast.parse(request['script'])
node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='payload' for t in n.targets))
p=json.loads(ast.literal_eval(node.value.args[0]))
p.update(configPath=str(path),caddyBinary=str(root/'caddy'),systemctlBinary=str(root/'systemctl'))
r=transaction(p)
if r['backupPath'] is not None: r['backupPath']='/etc/caddy/.swamp-caddy-backups/'+pathlib.Path(r['backupPath']).name
print(json.dumps(r))
`;
  const ctx: Parameters<typeof model.methods.inspect.execute>[1] = {
    globalArgs: { sshModel: "YOUR_SSH_MODEL", host: "YOUR_HOST" },
    signal: new AbortController().signal,
    logger: { info: () => {} },
    definitionRepository: {
      findByNameGlobal: (name) =>
        Promise.resolve(name === "YOUR_SSH_MODEL" ? target : null),
      findAllByIdGlobal: () => Promise.resolve([target]),
    },
    runModel: async (request) => {
      // Synthetic transport: real Python transaction and disposable local
      // commands, NOT an SSH connection, systemd service or native child run.
      const child = new Deno.Command("python3", {
        args: ["-c", driver + fixture],
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
      }).spawn();
      const writer = child.stdin.getWriter();
      await writer.write(
        new TextEncoder().encode(
          JSON.stringify({ root, script: request.arguments.script }),
        ),
      );
      await writer.close();
      const output = await child.output();
      if (!output.success) {
        throw new Error(new TextDecoder().decode(output.stderr));
      }
      const result = {
        ...JSON.parse(new TextDecoder().decode(output.stdout)),
        ...tamper,
      };
      const stdout = JSON.stringify(result);
      return {
        ok: true,
        resources: [{
          kind: "resource",
          specName: "runResult",
          name: "run-script-YOUR_HOST",
          version: ++version,
          size: stdout.length,
          metadata: {
            ownerDefinition: { ownerType: "model-method", ownerRef: modelId },
          },
          attributes: {
            host: "YOUR_HOST",
            method: "script",
            exitCode: 0,
            signal: null,
            stdout,
          },
        }],
      };
    },
    writeResource: (_spec, _name, value) => {
      stored.push(value);
      return Promise.resolve({ name: "operation" });
    },
  };
  const route = {
    name: "notes",
    hostname: "notes.example.com",
    wildcardDomain: "example.com",
    upstream: "192.0.2.20:8000",
    upstreamScheme: "http",
    allowedCidrs: [
      "192.0.2.0/24",
      "2001:0DB8:0000:0000:0000:0000:0000:0000/64",
    ],
    expectedSha256: "",
  };
  try {
    await model.methods.inspect.execute({}, ctx);
    route.expectedSha256 = String(stored.at(-1)?.beforeSha256);
    const original = await Deno.readTextFile(root + "/Caddyfile");
    await model.methods.plan.execute(route, ctx);
    assertEquals(await Deno.readTextFile(root + "/Caddyfile"), original);
    assertEquals(
      stored.at(-1)?.route,
      [
        "    # BEGIN swamp-caddy notes",
        "    @swamp_notes host notes.example.com",
        "    handle @swamp_notes {",
        "        @outside_notes not remote_ip 192.0.2.0/24 2001:db8::/64",
        '        respond @outside_notes "Forbidden" 403',
        "        reverse_proxy 192.0.2.20:8000",
        "    }",
        "    # END swamp-caddy notes",
        "",
      ].join("\n"),
    );
    const count = stored.length;
    for (
      const invalid of [
        { route: "PRIVATE_TEST_SENTINEL" },
        { beforeSha256: "b".repeat(64) },
        { validated: false },
        { serviceActive: false },
        { changed: false },
        {
          backupPath: "/etc/caddy/.swamp-caddy-backups/" + "a".repeat(64) +
            "-" + "b".repeat(32) + ".Caddyfile",
        },
        { extra: "PRIVATE_TEST_SENTINEL" },
      ]
    ) {
      tamper = invalid;
      const error = await assertRejects(() =>
        model.methods.plan.execute(route, ctx)
      );
      assertEquals(String(error).includes("PRIVATE_TEST_SENTINEL"), false);
      assertEquals(stored.length, count);
    }
    tamper = null;
    await model.methods.apply.execute(route, ctx);
    assertEquals(stored.at(-1)?.changed, true);
    assertEquals(
      (await Deno.readTextFile(root + "/Caddyfile")).includes("@swamp_notes"),
      true,
    );
    route.expectedSha256 = String(stored.at(-1)?.afterSha256);
    await model.methods.apply.execute(route, ctx);
    assertEquals(stored.at(-1)?.changed, false);
    assertEquals(stored.at(-1)?.backupPath, null);
    const removal = {
      name: route.name,
      hostname: route.hostname,
      wildcardDomain: route.wildcardDomain,
      expectedSha256: route.expectedSha256,
    };
    await model.methods.remove.execute(removal, ctx);
    assertEquals(await Deno.readTextFile(root + "/Caddyfile"), original);
    assertEquals(stored.at(-1)?.route, null);
    assertEquals(stored.at(-1)?.changed, true);
    removal.expectedSha256 = String(stored.at(-1)?.afterSha256);
    await model.methods.remove.execute(removal, ctx);
    assertEquals(stored.at(-1)?.changed, false);
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
