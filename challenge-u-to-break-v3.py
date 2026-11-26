#!/usr/bin/env python3
"""QuantumVault independent local adversarial challenge V3. Python 3.11+.
Run from your OWN repository: python challenge-u-to-break-v3.py --repo .
No network requests, no real credentials, no existing database modification.
All adapter calls use fresh subprocesses and disposable synthetic state.
Optional --extended runs the project's own regression suite separately.
References: Track-4-Toolkit docs/adapter-v1.md; NIST FIPS 203; OWASP WSTG;
SQLite atomic commit/WAL documentation. Not an official or hidden judge test.
"""
import argparse, base64, concurrent.futures, hashlib, hmac, json, os
from pathlib import Path
import random, secrets, subprocess, sys, tempfile, time, sqlite3, threading, unicodedata

class Skip(Exception): pass
class Finding(Exception): pass

def require(condition, message):
    if not condition: raise Finding(message)

def strict_json(raw):
    def pairs(items):
        out = {}
        for k,v in items:
            if k in out: raise ValueError('duplicate response key')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs)

class Challenge:
    def __init__(self, root, scratch, seed):
        self.root, self.scratch = root, scratch
        self.rng = random.Random(seed)
        self.marker = 'QV_TEST_SECRET_' + secrets.token_hex(24)
        self.a = 'Actor_' + secrets.token_hex(8)
        self.b = self.a.lower()
        self.c = 'disabled_' + secrets.token_hex(8)
        self.x, self.y, self.z = ['asset_' + secrets.token_hex(8) for _ in range(3)]
        self.body = 'QV_BODY_' + secrets.token_hex(18) + '\nUnicode: ಕನ್ನಡ 🔐\r\n'
        self.peer = 'QV_PEER_' + secrets.token_hex(18)
        self.disabled_body = 'QV_DISABLED_' + secrets.token_hex(18)
        self.results=[]; self.calls=0; self._count_lock=threading.Lock()
    def env(self, state):
        e = os.environ.copy()
        e.update(TRACK4_STATE_DIR=str(state), TMPDIR=str(state), TEMP=str(state), TMP=str(state), PYTHONIOENCODING='utf-8', PYTHONDONTWRITEBYTECODE='1')
        return e
    def raw(self,state,payload):
        with self._count_lock:self.calls += 1
        try:
            p=subprocess.run([sys.executable,str(self.root/'track4_service.py')],input=payload,capture_output=True,cwd=self.root,env=self.env(state),timeout=8)
        except subprocess.TimeoutExpired: raise Finding('adapter exceeded 8-second test budget') from None
        require(len(p.stdout)<=65536 and len(p.stderr)<=65536,'output exceeds 64 KiB test budget')
        require(self.marker.encode() not in p.stdout+p.stderr,'synthetic key marker leaked')
        for value in (self.body,self.peer,self.disabled_body):
            # random prefixes also catch escaped or partially printed bodies
            require(value.split('\n')[0].encode() not in p.stderr,'protected content leaked into diagnostics')
        return p
    def call(self,state,op,**kw):
        p=self.raw(state,json.dumps(dict(op=op,**kw),ensure_ascii=False).encode())
        require(p.returncode==0,f'{op}: nonzero exit ({p.returncode})')
        try: r=strict_json(p.stdout.decode('utf-8'))
        except (ValueError,UnicodeError): raise Finding(f'{op}: invalid JSON output') from None
        require(isinstance(r,dict),f'{op}: response not an object')
        return r
    def state(self):
        return Path(tempfile.mkdtemp(prefix='case-',dir=self.scratch))
    def setup(self,s,empty=False):
        r=self.call(s,'setup',owners={self.x:self.a,self.y:self.b,self.z:self.c},contents={self.x:self.body,self.y:'' if empty else self.peer,self.z:self.disabled_body},disabled=[self.c],key_material=self.marker)
        require(r.get('ready') is True,'setup did not succeed')
    def req(self,s,a,x,rid=None):
        return self.call(s,'read',actor=a,asset=x,request_id=rid or secrets.token_hex(12))
    def deny(self,r):
        require(r.get('decision')=='deny','unauthorized request was not denied')
        require(not any(k in r for k in ('body','proof','ciphertext')),'denial contains protected response fields')
        serialized=json.dumps(r,ensure_ascii=False)
        require(not any(v.split('\n')[0] in serialized for v in (self.body,self.peer,self.disabled_body)),'denial leaks synthetic protected content')
    def allow(self,r,body):
        require(r.get('decision')=='allow' and r.get('body')==body,'authorized response missing or changed exact body')
        serialized=json.dumps(r,ensure_ascii=False)
        for other in (self.body,self.peer,self.disabled_body):
            if other!=body: require(other.split('\n')[0] not in serialized,'unrelated protected content leaked')
    def audit(self,s,rid,decision):
        r=self.call(s,'audit',request_id=rid)
        require(r.get('request_id')==rid and r.get('decision')==decision,'audit decision or request ID mismatch')
    def run(self,name,kind,fn):
        t=time.perf_counter()
        try: fn(); status='PASS'; detail='invariant held'
        except Skip as e: status='SKIP'; detail=str(e)
        except Finding as e: status='FAIL'; detail=str(e)
        except Exception as e: status='ERROR'; detail=type(e).__name__+' (inspect locally; exception text omitted)'
        row=dict(test=name,category=kind,status=status,detail=detail,ms=round((time.perf_counter()-t)*1000,2))
        self.results.append(row); print(f'{status:5} [{kind}] {name}: {detail}',flush=True)
    def ownership(self):
        s=self.state(); self.setup(s)
        for a in (self.a,self.b,self.c,'unknown'):
            for x in (self.x,self.y,self.z,'missing'):
                rid=secrets.token_hex(12); r=self.req(s,a,x,rid)
                if (a,x)==(self.a,self.x): self.allow(r,self.body); d='allow'
                elif (a,x)==(self.b,self.y): self.allow(r,self.peer); d='allow'
                else: self.deny(r); d='deny'
                self.audit(s,rid,d)
    def revoke(self):
        s=self.state(); self.setup(s); old=secrets.token_hex(12)
        self.allow(self.req(s,self.a,self.x,old),self.body)
        self.call(s,'revoke',actor=self.a)
        self.call(s,'revoke',actor=self.a)
        for _ in range(3): self.deny(self.req(s,self.a,self.x)); self.allow(self.req(s,self.b,self.y),self.peer)
        self.audit(s,old,'allow')
    def isolation(self):
        s,t=self.state(),self.state(); self.setup(s); self.setup(t,empty=True)
        self.call(s,'revoke',actor=self.a)
        self.deny(self.req(s,self.a,self.x)); self.allow(self.req(t,self.a,self.x),self.body)
        self.allow(self.req(t,self.b,self.y),''); self.allow(self.req(s,self.b,self.y),self.peer)
        self.setup(s); self.allow(self.req(s,self.a,self.x),self.body)
    def duplicate_id(self):
        s=self.state(); self.setup(s); rid=secrets.token_hex(12)
        self.allow(self.req(s,self.a,self.x,rid),self.body); self.call(s,'revoke',actor=self.a)
        p=self.raw(s,json.dumps(dict(op='read',actor=self.a,asset=self.x,request_id=rid)).encode())
        require(self.body.split('\n')[0].encode() not in p.stdout,'duplicate request ID returned revoked plaintext')
        if p.returncode==0:
            r=strict_json(p.stdout.decode()); require(r.get('decision')!='allow','duplicate request ID bypassed revocation')
        self.audit(s,rid,'allow')
    def opaque(self):
        s=self.state(); a="test ' \" \n actor ಕನ್ನಡ"; x='asset/../opaque 🔐'; rid='request\nsecond-record'
        r=self.call(s,'setup',owners={x:a},contents={x:self.body},disabled=[],key_material=self.marker)
        require(r.get('ready') is True,'opaque identifiers setup failed')
        self.allow(self.req(s,a,x,rid),self.body); self.audit(s,rid,'allow')
        self.deny(self.req(s,a+' ',x))
    def malformed(self):
        s=self.state(); self.setup(s)
        payloads=[b'{',b'[]',b'null',b'\xff',b'{}\n{}',b'{"op":"unknown"}',b'{"op":"read","actor":null}',b'{"op":"read","actor":[]}',b'{"op":"setup","op":"read"}']
        for payload in payloads:
            p=self.raw(s,payload)
            require(not any(v.split('\n')[0].encode() in p.stdout for v in (self.body,self.peer,self.disabled_body)),'malformed input leaked protected content')
            if p.returncode==0:
                try:r=strict_json(p.stdout.decode())
                except ValueError:raise Finding('malformed request produced invalid successful output') from None
                require(isinstance(r,dict) and r.get('decision')!='allow' and r.get('ready') is not True,'malformed input reported successful protected operation')
        self.allow(self.req(s,self.a,self.x),self.body)
    def pqc(self):
        try: from pqcrypto.kem import ml_kem_768 as kem
        except ImportError: raise Skip('install project pqcrypto==0.4.0 in this interpreter') from None
        s=self.state(); self.setup(s); seen=set()
        for _ in range(5):
            pk,sk=kem.generate_keypair(); challenge='challenge 🔐 '+secrets.token_hex(16)
            args=dict(actor=self.a,asset=self.x,challenge=challenge,public_key=base64.b64encode(pk).decode())
            r=self.call(s,'protected_read',**args)
            require(isinstance(r.get('ciphertext'),str) and isinstance(r.get('proof'),str),'missing KEM fields')
            try: ct=base64.b64decode(r['ciphertext'],validate=True)
            except ValueError: raise Finding('invalid ciphertext Base64') from None
            require(len(ct)==1088,'incorrect ML-KEM-768 ciphertext size')
            require(ct not in seen,'repeated ciphertext across fresh exchanges');seen.add(ct)
            ss=kem.decrypt(sk,ct); expected=hmac.new(ss,(challenge+self.body).encode(),hashlib.sha256).hexdigest()
            require(hmac.compare_digest(expected,r['proof']),'independent KEM/HMAC verification failed')
            require('body' not in r,'protected_read returned plaintext')
            require(ss.hex() not in json.dumps(r) and base64.b64encode(ss).decode() not in json.dumps(r),'shared secret leaked')
            for actor in (self.b,self.c,'unknown'):
                self.deny(self.call(s,'protected_read',**dict(args,actor=actor)))
        self.call(s,'revoke',actor=self.a); self.deny(self.call(s,'protected_read',**args))
    def bad_keys(self):
        s=self.state();self.setup(s)
        for key in ('!', '',base64.b64encode(b'\0'*1183).decode(),base64.b64encode(b'\0'*1185).decode()):
            p=self.raw(s,json.dumps(dict(op='protected_read',actor=self.a,asset=self.x,challenge='test',public_key=key)).encode())
            require(self.body.split('\n')[0].encode() not in p.stdout,'invalid key exposed plaintext')
            if p.returncode==0:
                r=strict_json(p.stdout.decode()); require(not any(k in r for k in ('body','ciphertext','proof')),'malformed public key yielded protected output')
        self.allow(self.req(s,self.a,self.x),self.body)
    def race(self):
        s=self.state(); self.setup(s)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f=[pool.submit(self.req,s,self.a,self.x) for _ in range(2)]
            rev=pool.submit(self.call,s,'revoke',actor=self.a)
            rev.result()
            for item in f:
                r=item.result()
                if r.get('decision')=='allow':self.allow(r,self.body)
                else:self.deny(r)
            for item in [pool.submit(self.req,s,self.a,self.x) for _ in range(3)]:self.deny(item.result())
        self.allow(self.req(s,self.b,self.y),self.peer)
    def randomized(self):
        s=self.state(); self.setup(s); disabled={self.c}
        for i in range(18):
            if i==7:self.call(s,'revoke',actor=self.a);disabled.add(self.a)
            a=self.rng.choice([self.a,self.b,self.c,'unknown']); x=self.rng.choice([self.x,self.y,self.z,'unknown']); rid=secrets.token_hex(12)
            owner={self.x:self.a,self.y:self.b,self.z:self.c}.get(x)
            r=self.req(s,a,x,rid)
            if a==owner and a not in disabled:self.allow(r,{self.x:self.body,self.y:self.peer}[x]);d='allow'
            else:self.deny(r);d='deny'
            self.audit(s,rid,d)
    def extended(self):
        s=self.state()
        p=subprocess.run([sys.executable,'-m','unittest','discover','tests','-v'],cwd=self.root,env=self.env(s),capture_output=True,timeout=180)
        require(p.returncode==0,'project regression suite returned nonzero; run locally for details')


class StrongChallenge(Challenge):
    def call(self,state,op,**kw):
        r=super().call(state,op,**kw)
        if op != 'audit' and r.get('decision')=='deny':
            require(r=={'decision':'deny'},'denial differs from exact public response shape')
        return r

    def no_disclosure(self,p):
        for value in (self.body,self.peer,self.disabled_body,self.marker):
            require(value.split('\n')[0].encode() not in p.stdout+p.stderr,'synthetic secret disclosed')
        if p.returncode==0:
            try:r=strict_json(p.stdout.decode('utf-8'))
            except (ValueError,UnicodeError):raise Finding('successful exit with malformed response') from None
            require(isinstance(r,dict),'response not object')
            require(r.get('decision')!='allow' and r.get('ready') is not True,'invalid request accepted')
            require(not any(k in r for k in ('body','proof','ciphertext')),'invalid request returned protected fields')

    def parser_atomicity(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        bad=[b'{"op":"setup","owners":{},"contents":{},"disabled":[],"key_material":null}',
             b'{"op":"setup","owners":[],"contents":{},"disabled":[],"key_material":"test"}',
             b'{"op":"setup","owners":{"x":"a","x":"b"},"contents":{"x":"test"},"disabled":[],"key_material":"test"}',
             b'{"op":"revoke","actor":NaN}',b'{"op":"read","actor":true,"asset":false,"request_id":[]}',
             b'{"op":"read","actor":"\\ud800","asset":"x","request_id":"r"}',
             b'{"op":"revoke","actor":{"id":"x"}}',b'{"op":"setup"} trailing']
        for raw in bad:
            self.no_disclosure(self.raw(s,raw))
            self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def normalization(self):
        s=self.state();a='caf\u00e9';b=unicodedata.normalize('NFD',a);x='asset\u00e9';y=unicodedata.normalize('NFD',x)
        require(a!=b and x!=y,'bad fixture')
        require(self.call(s,'setup',owners={x:a,y:b},contents={x:self.body,y:self.peer},disabled=[],key_material=self.marker).get('ready') is True,'setup failed')
        for actor,asset,body in [(a,x,self.body),(b,y,self.peer)]:self.allow(self.req(s,actor,asset),body)
        self.deny(self.req(s,a,y));self.deny(self.req(s,b,x));self.call(s,'revoke',actor=a)
        self.deny(self.req(s,a,x));self.allow(self.req(s,b,y),self.peer)

    def audit_collision(self):
        s=self.state();self.setup(s);rid=secrets.token_hex(12)
        self.deny(self.req(s,self.b,self.x,rid));self.audit(s,rid,'deny')
        p=self.raw(s,json.dumps(dict(op='read',actor=self.a,asset=self.x,request_id=rid)).encode())
        if p.returncode==0:
            r=strict_json(p.stdout.decode());require(isinstance(r,dict),'invalid response')
            if r.get('decision')=='allow':raise Finding('conflicting request ID returned allow while original audit remains deny')
            require('body' not in r,'conflicting request disclosed body')
        self.audit(s,rid,'deny');self.allow(self.req(s,self.a,self.x),self.body)

    def parallel_revocations(self):
        s=self.state();self.setup(s);bar=threading.Barrier(3)
        def task(a):bar.wait(timeout=5);return self.call(s,'revoke',actor=a)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            fs=[pool.submit(task,a) for a in (self.a,self.b,self.c)]
            for f in fs:f.result(timeout=20)
        for a,x in ((self.a,self.x),(self.b,self.y),(self.c,self.z)):self.deny(self.req(s,a,x))

    def pqc_binding(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair();_,wrong=kem.generate_keypair()
        for asset,actor,body in [(self.x,self.a,self.body),(self.y,self.b,self.peer)]:
            challenge='\u0000challenge\n'+secrets.token_hex(12)
            args=dict(actor=actor,asset=asset,challenge=challenge,public_key=base64.b64encode(pk).decode())
            for _ in range(3):
                r=self.call(s,'protected_read',**args);ct=base64.b64decode(r['ciphertext'],validate=True);ss=kem.decrypt(sk,ct)
                proof=lambda k,m:hmac.new(k,m.encode(),hashlib.sha256).hexdigest()
                require(len(ct)==1088 and hmac.compare_digest(r['proof'],proof(ss,challenge+body)),'independent proof mismatch')
                require(r['proof']!=proof(ss,challenge+'x'+body),'challenge not bound')
                require(r['proof']!=proof(ss,challenge+body+'x'),'body not bound')
                require(r['proof']!=proof(kem.decrypt(wrong,ct),challenge+body),'wrong decapsulation key verified')
                require('body' not in r,'protected_read exposed plaintext')
            self.call(s,'revoke',actor=actor);self.deny(self.call(s,'protected_read',**args))

    def files(self,s):
        return [p for p in s.rglob('*') if p.is_file() and not p.is_symlink()]
    def databases(self,s):
        out=[]
        for p in self.files(s):
            try:
                with p.open('rb') as f:
                    if f.read(16)==b'SQLite format 3\x00':out.append(p)
            except (OSError, PermissionError):
                pass
        return out

    def disk_plaintext(self):
        s=self.state();self.setup(s);self.allow(self.req(s,self.a,self.x),self.body);self.deny(self.req(s,self.b,self.x))
        files=self.files(s)
        if not files:raise Skip('no persistent files discovered under isolated state')
        for p in files:
            if p.stat().st_size>16*1024*1024:raise Skip('fixture exceeds bounded scan size')
            data=p.read_bytes()
            for value in (self.body,self.peer,self.disabled_body):
                require(value.split('\n')[0].encode() not in data,'plaintext resource marker found in persistent state: '+p.name)

    def sqlite_integrity(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        dbs=self.databases(s)
        if not dbs:raise Skip('no SQLite database discovered')
        for p in dbs:
            db = sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3)
            try:
                require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity check failed')
                require(not db.execute('PRAGMA foreign_key_check').fetchone(),'foreign-key integrity violation')
            finally:
                db.close()
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def ciphertext_corruption(self):
        s=self.state();self.setup(s)
        changed=False
        for p in self.databases(s):
            db=sqlite3.connect(p,timeout=3)
            try:
                names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'assets' not in names:continue
                cols={r[1] for r in db.execute('PRAGMA table_info(assets)')}
                idcol=next((c for c in ('asset_id','id','resource_id') if c in cols),None)
                blobcol=next((c for c in ('ciphertext','encrypted_body','encrypted_content','body_ciphertext','encrypted_data','encrypted_blob') if c in cols),None)
                if not idcol or not blobcol:continue
                row=db.execute(f'SELECT "{blobcol}" FROM assets WHERE "{idcol}"=?',(self.x,)).fetchone()
                if not row or not isinstance(row[0],bytes) or not row[0]:continue
                damaged=bytearray(row[0]);damaged[len(damaged)//2]^=1
                db.execute(f'UPDATE assets SET "{blobcol}"=? WHERE "{idcol}"=?',(bytes(damaged),self.x))
                db.commit()
                changed=True
                break
            finally:
                db.close()
        if not changed:raise Skip('asset ciphertext column not recognized; inspect actual schema')
        p=self.raw(s,json.dumps(dict(op='read',actor=self.a,asset=self.x,request_id=secrets.token_hex(12))).encode())
        self.no_disclosure(p);self.allow(self.req(s,self.b,self.y),self.peer)

    def abrupt_exit(self):
        for delay in (0.01,0.05,0.12):
            s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
            payload=json.dumps(dict(op='read',actor=self.b,asset=self.y,request_id=secrets.token_hex(12))).encode()
            p=subprocess.Popen([sys.executable,str(self.root/'track4_service.py')],cwd=self.root,env=self.env(s),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                p.stdin.write(payload);p.stdin.close();p.stdin=None
                time.sleep(delay)
                if p.poll() is None:p.kill()
                p.communicate(timeout=8)
            finally:
                if p.poll() is None:p.kill();p.communicate()
            self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
            for dbpath in self.databases(s):
                db = sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True,timeout=3)
                try:
                    require(db.execute('PRAGMA integrity_check').fetchone()==('ok',),'database corrupt after process exit')
                finally:
                    db.close()

    def cross_state_key_binding(self):
        s,t=self.state(),self.state();self.setup(s);self.setup(t,empty=True)
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        pk,sk=kem.generate_keypair();challenge=secrets.token_hex(12)
        args=dict(actor=self.b,asset=self.y,challenge=challenge,public_key=base64.b64encode(pk).decode())
        for state,body in ((s,self.peer),(t,'')):
            r=self.call(state,'protected_read',**args);ss=kem.decrypt(sk,base64.b64decode(r['ciphertext'],validate=True));expected=hmac.new(ss,(challenge+body).encode(),hashlib.sha256).hexdigest()
            require(hmac.compare_digest(expected,r['proof']),'protected_read state/body binding mismatch')
        self.call(s,'revoke',actor=self.b);self.deny(self.call(s,'protected_read',**args));r=self.call(t,'protected_read',**args);require('proof' in r,'independent state incorrectly revoked')

    def random_deep(self):
        s=self.state();self.setup(s);disabled={self.c};history={}
        for i in range(36):
            if i in (11,24):
                a=(self.a,self.b)[i==24];self.call(s,'revoke',actor=a);disabled.add(a)
            a=self.rng.choice([self.a,self.b,self.c,'unknown']);x=self.rng.choice([self.x,self.y,self.z,'unknown']);rid=secrets.token_hex(12)
            owner={self.x:self.a,self.y:self.b,self.z:self.c}.get(x);r=self.req(s,a,x,rid)
            if a==owner and a not in disabled:self.allow(r,{self.x:self.body,self.y:self.peer}[x]);d='allow'
            else:self.deny(r);d='deny'
            history[rid]=d;self.audit(s,rid,d)
            if i%6==0:
                old=self.rng.choice(list(history));self.audit(s,old,history[old])
        for rid in list(history)[::4]:self.audit(s,rid,history[rid])


def main():
    ap=argparse.ArgumentParser(description='QuantumVault V3: bounded local independent adversarial regression')
    ap.add_argument('--repo',type=Path,default=Path('.'));ap.add_argument('--seed',type=int,default=41026);ap.add_argument('--extended',action='store_true');ap.add_argument('--report',type=Path,default=Path('challenge-u-to-break-v3-results.json'));ap.add_argument('--only',help='run groups containing this substring');args=ap.parse_args()
    root=args.repo.resolve()
    if not (root/'track4_service.py').is_file():ap.error('point --repo at your own QuantumVault repository root')
    if args.report.exists():
        args.report.unlink()
    with tempfile.TemporaryDirectory(prefix='qv-v3-independent-', ignore_cleanup_errors=True) as tmp:
        c=StrongChallenge(root,Path(tmp),args.seed)
        tests=[('Ownership matrix','contract',c.ownership),('Persistent revocation','contract',c.revoke),('State isolation/reset','contract',c.isolation),('Duplicate after revocation','hardening',c.duplicate_id),('Opaque identifiers','contract',c.opaque),('Malformed input','hardening',c.malformed),('Independent KEM','contract',c.pqc),('Malformed KEM keys','hardening',c.bad_keys),('Concurrent read/revoke','hardening',c.race),('Parser failure atomicity','hardening',c.parser_atomicity),('Unicode normalization isolation','contract',c.normalization),('Conflicting audit IDs','hardening',c.audit_collision),('Parallel distinct revocations','hardening',c.parallel_revocations),('KEM challenge/body/key binding','contract',c.pqc_binding),('Disk plaintext markers','storage',c.disk_plaintext),('SQLite integrity','storage',c.sqlite_integrity),('Ciphertext corruption isolation','storage',c.ciphertext_corruption),('Abrupt adapter exit/reopen','resilience',c.abrupt_exit),('Cross-state KEM binding','contract',c.cross_state_key_binding),('Randomized historical oracle','contract',c.random_deep)]
        if args.extended:tests.append(('Existing project regression suite','project-owned',c.extended))
        selected=[t for t in tests if not args.only or args.only.casefold() in t[0].casefold()]
        if not selected:ap.error('no groups match --only')
        for name,kind,fn in selected:c.run(name,kind,fn)
        counts={k:sum(r['status']==k for r in c.results) for k in ('PASS','FAIL','ERROR','SKIP')}
        report=dict(version=3,seed=args.seed,adapter_calls=c.calls,counts=counts,results=c.results,limitations=['No independent internal IPC, web, recovery-code, outbox or messaging protocol coverage without actual source/API access.','Storage schema-dependent checks can skip.','Abrupt exits are timing-based, not proven mid-transaction kills.','Malformed input and conflicting audit IDs are additional hardening expectations, not fully specified by the public contract.','Not an official judge suite or formal proof.'])
        args.report.write_text(json.dumps(report,indent=2),encoding='utf-8');print('SUMMARY',counts,'| adapter calls:',c.calls,'| report:',args.report)
        return 1 if counts['FAIL'] or counts['ERROR'] else 2 if counts['SKIP'] else 0
if __name__=='__main__':sys.exit(main())
