#!/usr/bin/env python3
"""QuantumVault independent local adversarial challenge V5. Python 3.11+.
Run from your OWN repository: python challenge-u-to-break-v5.py --repo .
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
        # Small bounded local concurrency, no shared service traffic.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f=[pool.submit(self.req,s,self.a,self.x) for _ in range(2)]
            rev=pool.submit(self.call,s,'revoke',actor=self.a)
            rev.result()
            for item in f:
                r=item.result()
                if r.get('decision')=='allow':self.allow(r,self.body)
                else:self.deny(r)
            # These probes start only AFTER the durable revoke acknowledgement.
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
        # Existing project tests are explicitly opt-in and not independent evidence.
        s=self.state()
        p=subprocess.run([sys.executable,'-m','unittest','discover','tests','-v'],cwd=self.root,env=self.env(s),capture_output=True,timeout=180)
        require(p.returncode==0,'project regression suite returned nonzero; run locally for details')


class StrongChallenge(Challenge):
    def call(self,state,op,**kw):
        r=super().call(state,op,**kw)
        if op in ('read','protected_read') and r.get('decision')=='deny':
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
        # Malformed setup must not partially reset revocations. No large payloads.
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
        # A conflicting reuse may be refused, but must not overwrite audit history.
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
            with p.open('rb') as f:
                if f.read(16)==b'SQLite format 3\x00':out.append(p)
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
            with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3) as db:
                require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity check failed')
                require(not db.execute('PRAGMA foreign_key_check').fetchone(),'foreign-key integrity violation')
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def ciphertext_corruption(self):
        s=self.state();self.setup(s)
        # Discover only a resource row matching our synthetic asset, never arbitrary tables.
        changed=False
        for p in self.databases(s):
            with sqlite3.connect(p,timeout=3) as db:
                names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'assets' not in names:continue
                cols={r[1] for r in db.execute('PRAGMA table_info(assets)')}
                idcol=next((c for c in ('asset_id','id','resource_id') if c in cols),None)
                blobcol=next((c for c in ('ciphertext','encrypted_body','encrypted_content','body_ciphertext','encrypted_data','encrypted_blob') if c in cols),None)
                if not idcol or not blobcol:continue
                row=db.execute(f'SELECT "{blobcol}" FROM assets WHERE "{idcol}"=?',(self.x,)).fetchone()
                if not row or not isinstance(row[0],bytes) or not row[0]:continue
                damaged=bytearray(row[0]);damaged[len(damaged)//2]^=1
                db.execute(f'UPDATE assets SET "{blobcol}"=? WHERE "{idcol}"=?',(bytes(damaged),self.x));changed=True;break
        if not changed:raise Skip('asset ciphertext column not recognized; inspect actual schema')
        p=self.raw(s,json.dumps(dict(op='read',actor=self.a,asset=self.x,request_id=secrets.token_hex(12))).encode())
        self.no_disclosure(p);self.allow(self.req(s,self.b,self.y),self.peer)

    def abrupt_exit(self):
        # Kill at a bounded wall-clock point, not a claimed deterministic commit hook.
        # The result may be before OR after commit; both must leave coherent state.
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
                with sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True,timeout=3) as db:
                    require(db.execute('PRAGMA integrity_check').fetchone()==('ok',),'database corrupt after process exit')

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


# V3 additions: independent state invariants and deterministic SQLite fault injection.
import re
import shutil

class BreakChallenge(StrongChallenge):
    def env(self, state):
        e = super().env(state)
        # Keep user Python settings from loading unexpected user startup hooks.
        e.pop('PYTHONSTARTUP', None)
        return e

    def setup_map(self, s, owners, bodies, disabled=(), key=None):
        r=self.call(s,'setup',owners=owners,contents=bodies,disabled=list(disabled),key_material=key or self.marker)
        require(r=={'ready':True},'setup response mismatch')

    def reject_raw(self,s,op,**kw):
        p=self.raw(s,json.dumps(dict(op=op,**kw),ensure_ascii=True).encode())
        self.no_disclosure(p)
        return p

    def no_init(self):
        s=self.state()
        self.reject_raw(s,'read',actor=self.a,asset=self.x,request_id='before-setup')
        self.setup(s);self.allow(self.req(s,self.a,self.x),self.body)

    def opaque_nul(self):
        s=self.state();a='prefix\x00suffix';b='prefix';x='doc\x00suffix';y='doc'
        self.setup_map(s,{x:a,y:b},{x:self.body,y:self.peer})
        for actor,asset,body in ((a,x,self.body),(b,y,self.peer)):
            rid='request\x00'+secrets.token_hex(5)
            self.allow(self.req(s,actor,asset,rid),body);self.audit(s,rid,'allow')
        self.deny(self.req(s,a,y));self.deny(self.req(s,b,x))
        self.call(s,'revoke',actor=a);self.deny(self.req(s,a,x));self.allow(self.req(s,b,y),self.peer)

    def multiple_assets(self):
        s=self.state(); owners={}; bodies={}
        for i in range(12):
            x='asset-'+secrets.token_hex(8);owners[x]=(self.a,self.b,self.c)[i%3];bodies[x]='content-'+secrets.token_hex(20)
        self.setup_map(s,owners,bodies,(self.c,))
        for x,a in owners.items():
            if a==self.c:self.deny(self.req(s,a,x))
            else:self.allow(self.req(s,a,x),bodies[x]);self.deny(self.req(s,self.c,x))
        self.call(s,'revoke',actor=self.a)
        for x,a in owners.items():
            if a==self.b:self.allow(self.req(s,a,x),bodies[x])
            else:self.deny(self.req(s,a,x))

    def reset_generation(self):
        s=self.state();self.setup(s);rid='old-'+secrets.token_hex(8)
        self.allow(self.req(s,self.a,self.x,rid),self.body);self.call(s,'revoke',actor=self.a)
        # Legitimate setup is the only authorized reset; the old generation must disappear.
        self.setup_map(s,{self.x:self.b},{self.x:self.peer},key=self.marker+'-next')
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.x),self.peer)
        self.deny(self.req(s,self.b,self.y));self.deny(self.req(s,self.c,self.z))
        self.deny(self.req(s,self.a,self.x,rid));self.audit(s,rid,'deny')

    def large_unicode(self):
        s=self.state();body=self.body+('aΩಕ🔐\n'*1800)
        require(len(json.dumps({'decision':'allow','body':body},ensure_ascii=True).encode())<65536,'bad fixture')
        self.setup_map(s,{self.x:self.a,self.y:self.b},{self.x:body,self.y:self.peer})
        self.allow(self.req(s,self.a,self.x),body);self.deny(self.req(s,self.b,self.x))
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def fallback_temp(self):
        s=self.state(); original=self.env
        def fallback(state):
            e=original(state);e.pop('TRACK4_STATE_DIR',None);return e
        self.env=fallback
        try:
            self.setup(s);self.allow(self.req(s,self.a,self.x),self.body);self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
            require(bool(self.files(s)),'no persistent state in designated temp fallback')
        finally:self.env=original

    def parallel_collision(self):
        s=self.state();self.setup(s);rid='collision-'+secrets.token_hex(8);bar=threading.Barrier(2)
        def task(a):
            bar.wait(timeout=5);return self.raw(s,json.dumps(dict(op='read',actor=a,asset=self.x,request_id=rid)).encode())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fs=[pool.submit(task,a) for a in (self.a,self.b)];pa,pb=[f.result(timeout=20) for f in fs]
        self.no_disclosure(pb)
        hist=self.call(s,'audit',request_id=rid)
        require(hist.get('request_id')==rid and hist.get('decision') in ('allow','deny'),'no coherent original audit entry')
        if pa.returncode==0:
            r=strict_json(pa.stdout.decode());
            if r.get('decision')=='allow':self.allow(r,self.body);require(hist['decision']=='allow','racing allow contradicts historical audit')
            else:self.no_disclosure(pa)
        else:self.no_disclosure(pa)
        self.allow(self.req(s,self.a,self.x),self.body)

    def protected_revoke_race(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode()
        def probe(actor,asset,body,expect):
            ch=secrets.token_hex(12);r=self.call(s,'protected_read',actor=actor,asset=asset,challenge=ch,public_key=pub)
            if r.get('decision')=='deny':self.deny(r);require(expect!='allow','unaffected peer denied')
            else:
                require(expect!='deny','KEM proof issued after revocation acknowledgement')
                ss=kem.decrypt(sk,base64.b64decode(r['ciphertext'],validate=True))
                require(hmac.compare_digest(r['proof'],hmac.new(ss,(ch+body).encode(),hashlib.sha256).hexdigest()),'concurrent KEM proof invalid')
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            fs=[pool.submit(probe,self.a,self.x,self.body,'either') for _ in range(2)]
            pool.submit(self.call,s,'revoke',actor=self.a).result(timeout=20)
            for f in fs:f.result(timeout=20)
            fs=[pool.submit(probe,self.a,self.x,self.body,'deny'),pool.submit(probe,self.b,self.y,self.peer,'allow')]
            for f in fs:f.result(timeout=20)

    def pqc_canonical_key(self):
        # FIPS 203 encapsulation input modulus check; a 1184-byte all-FF key
        # has noncanonical encoded polynomial coefficients. Additional hardening.
        s=self.state();self.setup(s)
        self.reject_raw(s,'protected_read',actor=self.a,asset=self.x,challenge='canonical-check',public_key=base64.b64encode(b'\xff'*1184).decode())
        self.allow(self.req(s,self.a,self.x),self.body)

    def _crypto_columns(self,db):
        cols={r[1] for r in db.execute('PRAGMA table_info(assets)')}
        ident=next((c for c in ('asset_id','id','resource_id') if c in cols),None)
        cipher=next((c for c in ('ciphertext','encrypted_body','encrypted_content','body_ciphertext','encrypted_data','encrypted_blob') if c in cols),None)
        if not ident or not cipher:return None
        bundle=[cipher]+[c for c in ('nonce','iv','tag','auth_tag','key_version','key_id','encryption_key_version','wrapped_dek','dek_nonce','wrapped_key') if c in cols and c!=cipher]
        return ident,bundle

    def swap_bundle(self,s,source,target):
        for path in self.databases(s):
            with sqlite3.connect(path,timeout=3) as db:
                layout=self._crypto_columns(db)
                if not layout:continue
                ident,cols=layout;select=','.join('"'+c+'"' for c in cols)
                row=db.execute(f'SELECT {select} FROM assets WHERE "{ident}"=?',(source,)).fetchone()
                old=db.execute(f'SELECT {select} FROM assets WHERE "{ident}"=?',(target,)).fetchone()
                if row is None or old is None or row==old:continue
                require(db.execute('UPDATE assets SET '+','.join('"'+c+'"=?' for c in cols)+f' WHERE "{ident}"=?',(*row,target)).rowcount==1,'fixture update failed')
                return
        raise Skip('asset schema not recognized for ciphertext-bundle swap')

    def cross_owner_swap(self):
        s=self.state();self.setup(s);self.swap_bundle(s,self.x,self.y)
        self.reject_raw(s,'read',actor=self.b,asset=self.y,request_id=secrets.token_hex(12))
        self.allow(self.req(s,self.a,self.x),self.body)

    def same_owner_swap(self):
        s=self.state();self.setup_map(s,{self.x:self.a,self.y:self.a,self.z:self.b},{self.x:self.body,self.y:self.disabled_body,self.z:self.peer})
        self.swap_bundle(s,self.x,self.y)
        self.reject_raw(s,'read',actor=self.a,asset=self.y,request_id=secrets.token_hex(12))
        self.allow(self.req(s,self.a,self.x),self.body);self.allow(self.req(s,self.b,self.z),self.peer)

    def nonce_uniqueness(self):
        s=self.state();owners={f'a{i}':self.a for i in range(48)};bodies={x:self.body for x in owners}
        self.setup_map(s,owners,bodies)
        for path in self.databases(s):
            with sqlite3.connect(path,timeout=3) as db:
                layout=self._crypto_columns(db)
                if not layout:continue
                ident,bundle=layout;nonce=next((c for c in ('nonce','iv') if c in bundle),None)
                if not nonce:continue
                rows=db.execute(f'SELECT "{ident}","{nonce}","{bundle[0]}" FROM assets').fetchall();rows=[r for r in rows if r[0] in owners]
                if len(rows)!=48:continue
                require(all(isinstance(r[1],(bytes,str)) and r[1] for r in rows),'missing nonce')
                require(len({r[1] for r in rows})==48,'reused nonce across equal-plaintext assets (inspect key scope)')
                require(len({r[2] for r in rows})==48,'identical ciphertext across equal-plaintext assets')
                return
        raise Skip('nonce/ciphertext schema unavailable')

    def anchor_corruption(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        anchors=[p for p in self.files(s) if p.name=='.cluster_epoch_anchor']
        if len(anchors)!=1:raise Skip('adapter does not expose a unique cluster epoch anchor in isolated state')
        p=anchors[0];original=p.read_bytes();require(bool(original),'empty epoch anchor')
        p.write_bytes(b'v1:corrupted:invalid\n')
        try:
            self.reject_raw(s,'read',actor=self.a,asset=self.x,request_id=secrets.token_hex(8))
            self.reject_raw(s,'read',actor=self.b,asset=self.y,request_id=secrets.token_hex(8))
        finally:p.write_bytes(original)
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def db_only_rollback(self):
        s=self.state();self.setup(s);snap=self.state();dbs=self.databases(s)
        if not dbs:raise Skip('no SQLite snapshot target')
        # Keep independent external anchors, keys and checkpoints current. Replace ONLY database images.
        backups=[]
        for i,p in enumerate(dbs):
            dest=snap/f'{i}.sqlite'
            src=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3);dst=sqlite3.connect(dest)
            try:src.backup(dst)
            finally:dst.close();src.close()
            backups.append((p,dest))
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
        anchors=[p for p in self.files(s) if p.name in ('.cluster_epoch_anchor','external_checkpoints.json')]
        if not anchors:raise Skip('no independently stored anchor discovered; direct database rollback is outside verified boundary')
        for p,dest in backups:
            # No active workers or connections in this isolated fixture.
            for suffix in ('-wal','-shm','-journal'):
                side=Path(str(p)+suffix)
                if side.exists():side.unlink()
            shutil.copyfile(dest,p)
        self.reject_raw(s,'read',actor=self.a,asset=self.x,request_id=secrets.token_hex(8))

    def _kill_before_commit(self, state, request, table_pattern):
        # Trace callback pauses BEFORE SQLite executes COMMIT. It is not a timing guess.
        # Hook is injected into a disposable subprocess, not into repository source.
        marker=self.state()/'boundary.txt'
        hook=r'''
import os, re, runpy, sqlite3, sys, time
from pathlib import Path
entry, marker, state, pattern = sys.argv[1:]
orig = sqlite3.connect
state=Path(state).resolve()
def connect(*a,**k):
    conn=orig(*a,**k)
    try:
        path=Path(a[0] if a else k['database']).resolve()
        if not path.is_relative_to(state):return conn
    except Exception:return conn
    touched=False
    def trace(sql):
        nonlocal touched
        norm=sql.strip()
        if re.match(r'^(ROLLBACK|END)\b',norm,re.I):touched=False
        if re.search(pattern,norm,re.I):touched=True
        if touched and re.match(r'^COMMIT\b',norm,re.I):
            Path(marker).write_text('pre-commit',encoding='ascii')
            while True:time.sleep(0.05)
    conn.set_trace_callback(trace)
    return conn
sqlite3.connect=connect
sys.path.insert(0,str(Path(entry).parent))
sys.argv=[entry]
runpy.run_path(entry,run_name='__main__')
'''
        payload=json.dumps(request,ensure_ascii=True).encode()
        p=subprocess.Popen([sys.executable,'-c',hook,str(self.root/'track4_service.py'),str(marker),str(state),table_pattern],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=self.root,env=self.env(state))
        reached=False
        try:
            p.stdin.write(payload);p.stdin.close();p.stdin=None
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                if marker.exists():reached=True;break
                if p.poll() is not None:break
                time.sleep(.01)
            if p.poll() is None:p.kill()
            p.communicate(timeout=8)
        finally:
            if p.poll() is None:p.kill();p.communicate()
        if not reached:raise Skip('target SQLite write/COMMIT trace not reached; no crash coverage claimed')
        require(p.returncode!=0,'fault subprocess was not terminated')

    def deterministic_revoke_crash(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        self._kill_before_commit(s,{'op':'revoke','actor':self.b},r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE)\s+["`\[]?(?:revocations|identities)\b')
        self.deny(self.req(s,self.a,self.x))
        # The attempted revoke may have advanced an external anchor before SQL commit.
        # Its outcome may be deny or allow, but no incorrect body may be returned.
        r=self.req(s,self.b,self.y)
        if r.get('decision')=='allow':self.allow(r,self.peer)
        else:self.deny(r)
        self.call(s,'revoke',actor=self.b);self.deny(self.req(s,self.b,self.y))
        for path in self.databases(s):
            with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3) as db:require(db.execute('PRAGMA integrity_check').fetchone()==('ok',),'database integrity failed after boundary kill')

    def deterministic_setup_crash(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        self._kill_before_commit(s,dict(op='setup',owners={self.x:self.a,self.y:self.b},contents={self.x:self.disabled_body,self.y:self.peer},disabled=[self.a],key_material=self.marker),r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|DELETE\s+FROM|UPDATE)\s+["`\[]?assets\b')
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
        for path in self.databases(s):
            with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3) as db:require(db.execute('PRAGMA integrity_check').fetchone()==('ok',),'database integrity failed after setup boundary kill')

    def concurrent_setup_snapshot(self):
        s=self.state();self.setup(s);bar=threading.Barrier(2)
        maps=[({self.x:self.a,self.y:self.b},{self.x:self.body,self.y:self.peer},[self.a]),({self.x:self.b,self.y:self.a},{self.x:self.disabled_body,self.y:self.body},[self.b])]
        def task(f):bar.wait(timeout=5);self.setup_map(s,*f)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fs=[pool.submit(task,f) for f in maps]
            for f in fs:f.result(timeout=20)
        # After both complete, final state must match one whole setup, never a mixture.
        observed=[]
        for a,x in ((self.a,self.x),(self.b,self.x),(self.a,self.y),(self.b,self.y)):
            r=self.req(s,a,x);observed.append((r.get('decision'),r.get('body')))
        expect1=[('deny',None),('deny',None),('deny',None),('allow',self.peer)]
        expect2=[('deny',None),('deny',None),('allow',self.body),('deny',None)]
        require(observed in (expect1,expect2),'concurrent setup left mixed or unusable state')

    def multiseed_oracle(self):
        # More balanced than a random matrix after all actors are revoked.
        for roundno in range(3):
            s=self.state();actors=[secrets.token_hex(6) for _ in range(5)];assets=[secrets.token_hex(7) for _ in range(5)]
            bodies={x:'QV_RANDOM_'+secrets.token_hex(20) for x in assets};owners=dict(zip(assets,actors));disabled=set();history={}
            self.setup_map(s,owners,bodies)
            for i in range(16):
                if i in (5,10):
                    a=actors[(i//5)-1];self.call(s,'revoke',actor=a);disabled.add(a)
                x=self.rng.choice(assets);a=owners[x] if i%2==0 else self.rng.choice(actors+['unknown']);rid=secrets.token_hex(12)
                r=self.req(s,a,x,rid);allow=a==owners[x] and a not in disabled
                if allow:self.allow(r,bodies[x])
                else:
                    self.deny(r);require(not any(v in json.dumps(r) for v in bodies.values()),'randomized secret leaked')
                history[rid]='allow' if allow else 'deny';self.audit(s,rid,history[rid])
            for rid in list(history)[::5]:self.audit(s,rid,history[rid])


# V4: bounded history-model checking, post-COMMIT crash and application boundary tests.
# References: Herlihy & Wing, Linearizability (1990),
# https://www.cs.columbia.edu/~wing/publications/HerlihyWing90.pdf
# SQLite backup API https://www.sqlite.org/backup.html and WAL docs.
from functools import lru_cache


def linearizable(initial, history, transition):
    """Exact search over all legal real-time-respecting orders of <= 16 completed ops.
    State must be hashable; transition returns next state or None if output is impossible.
    No assumption about the order of overlapping calls. Returns a witness or None.
    """
    n = len(history)
    if n > 16: raise ValueError('bounded checker supports at most 16 operations')
    predecessors = [sum(1 << j for j, h in enumerate(history)
                        if i != j and h['end'] <= history[i]['start']) for i in range(n)]
    all_done = (1 << n) - 1
    @lru_cache(maxsize=None)
    def search(mask, state):
        if mask == all_done: return ()
        for i, h in enumerate(history):
            bit = 1 << i
            if mask & bit or predecessors[i] & ~mask: continue
            nxt = transition(state, h)
            if nxt is None: continue
            rest = search(mask | bit, nxt)
            if rest is not None: return (i,) + rest
        return None
    return search(0, initial)


# Only the test child is instrumented. The repository source is not patched.
# Hooks pause BEFORE or AFTER an actual explicit SQLite COMMIT matching a prior
# write to a target table. A missing hook is SKIP, never a claimed successful kill.
COMMIT_HOOK = r'''
import os, re, runpy, sqlite3, sys, time
from pathlib import Path
entry, marker, state, pattern, phase = sys.argv[1:]
base = sqlite3.connect

def pause():
    Path(marker).write_text(phase, encoding='ascii')
    while True: time.sleep(.025)

class Conn(sqlite3.Connection):
    touched = False
    inside = False
    def observe(self, sql):
        if re.search(pattern, sql.strip(), re.I): self.touched = True
    def execute(self, sql, *a, **kw):
        self.observe(sql)
        hit = self.touched and re.match(r'^\s*(?:COMMIT|END)\b', sql, re.I)
        if hit and phase == 'before': pause()
        result = super().execute(sql, *a, **kw)
        if hit and phase == 'after': pause()
        if re.match(r'^\s*(?:COMMIT|END|ROLLBACK)\b', sql, re.I): self.touched = False
        return result
    def executemany(self, sql, *a, **kw):
        self.observe(sql); return super().executemany(sql,*a,**kw)
    def cursor(self,*a,**kw):
        if not a and 'factory' not in kw: kw['factory'] = Cur
        return super().cursor(*a,**kw)
    def commit(self):
        hit = self.touched and self.in_transaction
        if hit and phase == 'before': pause()
        result = super().commit()
        if hit and phase == 'after': pause()
        self.touched = False
        return result
    def rollback(self):
        result = super().rollback(); self.touched = False; return result

class Cur(sqlite3.Cursor):
    def execute(self,sql,*a,**kw):
        c=self.connection; c.observe(sql)
        hit = c.touched and re.match(r'^\s*(?:COMMIT|END)\b',sql,re.I)
        if hit and phase == 'before':pause()
        result=super().execute(sql,*a,**kw)
        if hit and phase == 'after':pause()
        if re.match(r'^\s*(?:COMMIT|END|ROLLBACK)\b',sql,re.I):c.touched=False
        return result
    def executemany(self,sql,*a,**kw):
        self.connection.observe(sql); return super().executemany(sql,*a,**kw)

def connect(database,*a,**kw):
    # Limit instrumentation to target test-state DB. No arbitrary external DB.
    try: inside = Path(database).resolve().is_relative_to(Path(state).resolve())
    except (ValueError,TypeError,OSError): inside=False
    if inside and len(a)<5 and 'factory' not in kw: kw['factory']=Conn
    return base(database,*a,**kw)
sqlite3.connect=connect
sys.path.insert(0,str(Path(entry).parent));sys.argv=[entry]
runpy.run_path(entry,run_name='__main__')
'''

WEB_PROBE = r'''
import importlib, json, sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
try:
    from fastapi.testclient import TestClient
    mod=importlib.import_module('quantumvault.web.app')
except ImportError:
    print(json.dumps({'skip':'web dependencies/module unavailable'}));sys.exit(0)
app=getattr(mod,'app',None)
if app is None:
    print(json.dumps({'skip':'module does not export ASGI app'}));sys.exit(0)
try: client=TestClient(app,base_url='http://localhost:8000',raise_server_exceptions=False)
except TypeError:
    print(json.dumps({'skip':'incompatible TestClient/httpx versions'}));sys.exit(0)
results={}
with client:
    probes=[('baseline','GET','/',{}),('bad_host','GET','/',{'Host':'untrusted.invalid'}),
            ('rotate_no_token','POST','/api/v1/auth/rotate',{}),
            ('logout_no_token','POST','/api/v1/auth/logout',{}),
            ('rotate_bad_token','POST','/api/v1/auth/rotate',{'X-Operator-Token':'invalid-synthetic-test-token'}),
            ('rotate_bad_origin','POST','/api/v1/auth/rotate',{'Origin':'http://untrusted.invalid','X-Operator-Token':'invalid-synthetic-test-token'})]
    for name,method,path,headers in probes:
        # Do not return response bodies or generated credentials to parent.
        r=client.request(method,path,headers=headers,follow_redirects=False)
        results[name]=r.status_code
print(json.dumps({'statuses':results}))
'''

class V4(BreakChallenge):
    def __init__(self,*args,rounds=4,**kwargs):
        super().__init__(*args,**kwargs);self.rounds=rounds;self.observations=[]

    def env(self,state):
        e=super().env(state)
        # Avoid user environment overrides accidentally importing another project.
        e.pop('PYTHONPATH',None)
        return e

    def history(self,s,ops):
        """Schedule a bounded overlapping batch; use monotonic invocation/response times."""
        barrier=threading.Barrier(len(ops)); history=[]
        def invoke(op):
            barrier.wait(timeout=10)
            time.sleep(op.get('delay',0))
            start=time.monotonic_ns()
            result=self.call(s,op['op'],**op['args'])
            end=time.monotonic_ns()
            return dict(op, result=result,start=start,end=end)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ops)) as pool:
            fs=[pool.submit(invoke,o) for o in ops]
            history=[f.result(timeout=30) for f in fs]
        return history

    def record_history(self,name,h,witness):
        # Do not expose fixture bodies, keys, or internal response ciphertexts.
        lo=min(x['start'] for x in h)
        rows=[]
        for i,x in enumerate(h):
            r=x['result']; a=x['args']; actor=a.get('actor'); asset=a.get('asset')
            rows.append(dict(index=i,op=x['op'],actor={self.a:'A',self.b:'B',self.c:'C'}.get(actor,'other' if actor else None),
                             asset={self.x:'X',self.y:'Y',self.z:'Z'}.get(asset,'other' if asset else None),
                             start_ns=x['start']-lo,end_ns=x['end']-lo,
                             decision=r.get('decision'),ready=r.get('ready'),proof_present='proof' in r))
        self.observations.append(dict(test=name,witness=list(witness) if witness is not None else None,history=rows))

    def test_linear_revoke(self):
        for _ in range(self.rounds):
            s=self.state();self.setup(s)
            ops=[]
            for a in (self.a,self.b):
                ops.append(dict(op='revoke',args={'actor':a},delay=self.rng.uniform(0,.08)))
            for a,x in ((self.a,self.x),(self.b,self.y),(self.a,self.y),(self.b,self.x),(self.c,self.z),(self.a,self.x),(self.b,self.y)):
                ops.append(dict(op='read',args=dict(actor=a,asset=x,request_id=secrets.token_hex(12)),delay=self.rng.uniform(0,.12)))
            h=self.history(s,ops)
            owners={self.x:self.a,self.y:self.b,self.z:self.c}; bodies={self.x:self.body,self.y:self.peer,self.z:self.disabled_body}
            def transition(disabled, item):
                a=item['args']['actor'];r=item['result']
                if item['op']=='revoke':return disabled|frozenset((a,)) if r=={} else None
                x=item['args']['asset'];allowed=owners.get(x)==a and a not in disabled
                exp={'decision':'allow','body':bodies[x]} if allowed else {'decision':'deny'}
                return disabled if r==exp else None
            w=linearizable(frozenset((self.c,)),h,transition);self.record_history('revoke',h,w)
            require(w is not None,'no legal sequential ordering explains concurrent revokes/reads')
            for row in h:
                if row['op']=='read':self.audit(s,row['args']['request_id'],row['result']['decision'])
            self.deny(self.req(s,self.a,self.x));self.deny(self.req(s,self.b,self.y))

    def test_linear_generations(self):
        for _ in range(max(2,self.rounds//2)):
            s=self.state();self.setup(s)
            # Generation 1 switches owner; generation 2 changes the body and owner again.
            gens=[({self.x:self.a,self.y:self.b},{self.x:self.body,self.y:self.peer},frozenset((self.c,))),
                  ({self.x:self.b,self.y:self.a},{self.x:self.disabled_body,self.y:self.body},frozenset()),
                  ({self.x:self.a,self.y:self.b},{self.x:self.peer,self.y:self.disabled_body},frozenset((self.b,)))]
            ops=[dict(op='setup',generation=i,args=dict(owners=gens[i][0],contents=gens[i][1],disabled=list(gens[i][2]),key_material=self.marker),delay=self.rng.uniform(0,.1)) for i in (1,2)]
            ops.append(dict(op='revoke',args={'actor':self.a},delay=self.rng.uniform(0,.1)))
            for a,x in ((self.a,self.x),(self.b,self.x),(self.a,self.y),(self.b,self.y),(self.a,self.x)):
                ops.append(dict(op='read',args=dict(actor=a,asset=x,request_id=secrets.token_hex(12)),delay=self.rng.uniform(0,.12)))
            h=self.history(s,ops)
            # Include final quiescent state in history so witness must explain it too.
            for a,x in ((self.a,self.x),(self.b,self.x),(self.a,self.y),(self.b,self.y)):
                args=dict(actor=a,asset=x,request_id=secrets.token_hex(12));start=time.monotonic_ns();r=self.call(s,'read',**args);h.append(dict(op='read',args=args,result=r,start=start,end=time.monotonic_ns()))
            def transition(st,item):
                gen,disabled=st;r=item['result'];op=item['op'];args=item['args']
                if op=='setup':
                    i=item['generation'];return (i,gens[i][2]) if r=={'ready':True} else None
                if op=='revoke':return (gen,disabled|frozenset((args['actor'],))) if r=={} else None
                a,x=args['actor'],args['asset'];owners,bodies,_=gens[gen]
                exp={'decision':'allow','body':bodies[x]} if owners.get(x)==a and a not in disabled else {'decision':'deny'}
                return st if r==exp else None
            w=linearizable((0,gens[0][2]),h,transition);self.record_history('setup-generations',h,w)
            require(w is not None,'mixed ownership/key/body generation observed; no atomic history exists')

    def test_linear_kem(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        for _ in range(max(2,self.rounds//2)):
            s=self.state();self.setup(s);pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode()
            ops=[dict(op='revoke',args={'actor':self.a},delay=self.rng.uniform(0,.07))]
            for a,x in ((self.a,self.x),(self.b,self.y),(self.a,self.x),(self.b,self.x),(self.b,self.y),(self.a,self.x)):
                ops.append(dict(op='protected_read',args=dict(actor=a,asset=x,challenge=secrets.token_hex(16)+' 🔐',public_key=pub),delay=self.rng.uniform(0,.1)))
            h=self.history(s,ops)
            for row in h:
                if row['op']!='protected_read':continue
                r=row['result'];args=row['args'];allowed_shape=r.get('decision')!='deny'
                if not allowed_shape:self.deny(r);continue
                require(set(r)=={'ciphertext','proof'},'protected read exposed unexpected output fields')
                ct=base64.b64decode(r['ciphertext'],validate=True);require(len(ct)==1088,'invalid ciphertext length')
                ss=kem.decrypt(sk,ct);body={self.x:self.body,self.y:self.peer}[args['asset']]
                expected=hmac.new(ss,(args['challenge']+body).encode(),hashlib.sha256).hexdigest()
                require(hmac.compare_digest(r['proof'],expected),'overlapping KEM request proof failed independent verification')
            def transition(disabled,item):
                a=item['args']['actor'];r=item['result']
                if item['op']=='revoke':return disabled|frozenset((a,)) if r=={} else None
                x=item['args']['asset'];allowed=(a,x) in ((self.a,self.x),(self.b,self.y)) and a not in disabled
                return disabled if allowed==('proof' in r) else None
            w=linearizable(frozenset((self.c,)),h,transition);self.record_history('kem-revoke',h,w)
            require(w is not None,'KEM proof/denial history contradicts real-time authorization model')
            self.deny(self.call(s,'protected_read',actor=self.a,asset=self.x,challenge='post-ack',public_key=pub))

    def commit_kill(self,s,request,phase,pattern):
        marker=self.scratch/('hook-'+secrets.token_hex(8))
        p=subprocess.Popen([sys.executable,'-c',COMMIT_HOOK,str(self.root/'track4_service.py'),str(marker),str(s),pattern,phase],cwd=self.root,env=self.env(s),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        reached=False
        try:
            p.stdin.write(json.dumps(request,ensure_ascii=True).encode());p.stdin.close();p.stdin=None
            until=time.monotonic()+8
            while time.monotonic()<until:
                if marker.exists():reached=True;break
                if p.poll() is not None:break
                time.sleep(.01)
            if p.poll() is None:p.kill()
            p.communicate(timeout=8)
        finally:
            if p.poll() is None:p.kill();p.communicate()
        if not reached:raise Skip('explicit SQLite commit hook not reached; no crash claim')
        require(p.returncode!=0,'subprocess did not terminate at observed boundary')
        self.observations.append(dict(test='commit-kill',phase=phase,hook_reached=True))

    def test_postcommit_revoke(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        self.commit_kill(s,dict(op='revoke',actor=self.b),'after',r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE)\s+["`\[]?(?:revocations|identities)\b')
        self.deny(self.req(s,self.a,self.x));self.deny(self.req(s,self.b,self.y))
        self.check_db(s)

    def test_postcommit_setup(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        self.commit_kill(s,dict(op='setup',owners={self.x:self.b,self.y:self.a},contents={self.x:self.peer,self.y:self.body},disabled=[self.a],key_material=self.marker),'after',r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+["`\[]?assets\b')
        self.deny(self.req(s,self.a,self.x));self.deny(self.req(s,self.a,self.y));self.allow(self.req(s,self.b,self.x),self.peer);self.deny(self.req(s,self.b,self.y));self.check_db(s)

    def check_db(self,s):
        dbs=self.databases(s)
        if not dbs:raise Skip('no isolated SQLite state discovered')
        for p in dbs:
            with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=3) as db:
                require(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'SQLite integrity check failed')
                require(not db.execute('PRAGMA foreign_key_check').fetchone(),'foreign key integrity check failed')

    def test_write_lock(self):
        s=self.state();self.setup(s);dbs=self.databases(s)
        if len(dbs)!=1:raise Skip('requires one unambiguous SQLite adapter DB')
        # Brief, bounded contention against our own temporary fixture only.
        conn=sqlite3.connect(dbs[0],timeout=2,isolation_level=None)
        try:
            conn.execute('BEGIN IMMEDIATE')
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                f=pool.submit(self.call,s,'revoke',actor=self.a)
                time.sleep(.35);conn.execute('ROLLBACK')
                require(f.result(timeout=15)=={},'revocation did not finish after writer lock released')
        finally:conn.close()
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer);self.check_db(s)

    def test_wire_limits(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        # Exactly 64 KiB input with trailing legal JSON whitespace; response small.
        valid=json.dumps(dict(op='read',actor=self.b,asset=self.y,request_id='limit-'+secrets.token_hex(8))).encode()
        p=self.raw(s,valid+b' '*(65536-len(valid)))
        require(p.returncode==0,'valid 64 KiB JSON request rejected (hardening expectation)')
        self.allow(strict_json(p.stdout.decode()),self.peer)
        # A valid JSON object beyond the project-reported input cap must not execute a reset.
        reset=json.dumps(dict(op='setup',owners={self.x:self.a},contents={self.x:self.body},disabled=[],key_material=self.marker)).encode()
        p=self.raw(s,reset+b' '*(65537-len(reset)));self.no_disclosure(p)
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def test_malformed_state(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        base=dict(op='setup',owners={self.x:self.a},contents={self.x:self.body},disabled=[],key_material=self.marker)
        # These cases deliberately violate field types or use ambiguous/non-JSON syntax.
        variants=[dict(base,owners=[]),dict(base,contents={self.x:None}),dict(base,disabled=''),dict(base,key_material=None),dict(base,owners={self.x:True}),dict(base,contents={self.x:float('nan')})]
        for request in variants:
            p=self.raw(s,json.dumps(request).encode());self.no_disclosure(p)
            self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
        # A nested duplicate asset mapping must not silently change state.
        raw=json.dumps(base).replace(json.dumps(self.x)+': '+json.dumps(self.a),json.dumps(self.x)+': '+json.dumps(self.a)+','+json.dumps(self.x)+': '+json.dumps(self.b),1).encode()
        p=self.raw(s,raw);self.no_disclosure(p);self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def test_audit_history_pressure(self):
        s=self.state();self.setup(s);hist=[]
        # IDs differ only by case, spaces, Unicode composition or embedded control characters.
        prefix=secrets.token_hex(8);ids=[prefix+x for x in ('A','a',' a','a ','é','e\u0301','\nX','\rX','\x00X')]
        for i,rid in enumerate(ids):
            a=self.a if i%2==0 else self.b;r=self.req(s,a,self.x,rid)
            if i%2==0:self.allow(r,self.body);d='allow'
            else:self.deny(r);d='deny'
            hist.append((rid,d))
        self.call(s,'revoke',actor=self.a)
        for rid,d in reversed(hist):
            p=self.raw(s,json.dumps(dict(op='read',actor=self.a,asset=self.x,request_id=rid)).encode());self.no_disclosure(p);self.audit(s,rid,d)
        self.allow(self.req(s,self.b,self.y),self.peer)

    def test_kem_multi_generation(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode();seen=set();ch='constant challenge 🔐'
        for i in range(4):
            body='QV_GENERATION_'+secrets.token_hex(24);self.setup_map(s,{self.x:self.a},{self.x:body},key=self.marker)
            args=dict(actor=self.a,asset=self.x,challenge=ch,public_key=pub)
            for _ in range(2):
                r=self.call(s,'protected_read',**args);require(set(r)=={'ciphertext','proof'},'unexpected proof shape')
                ct=base64.b64decode(r['ciphertext'],validate=True);require(len(ct)==1088 and ct not in seen,'invalid/repeated KEM ciphertext');seen.add(ct)
                ss=kem.decrypt(sk,ct);require(hmac.compare_digest(r['proof'],hmac.new(ss,(ch+body).encode(),hashlib.sha256).hexdigest()),'proof bound to stale generation')
                require(body not in json.dumps(r),'protected read leaked new generation body')
            self.call(s,'revoke',actor=self.a);self.deny(self.call(s,'protected_read',**args))

    def test_multi_snapshot(self):
        s=self.state();self.setup(s);dbs=self.databases(s)
        if len(dbs)!=1:raise Skip('requires one adapter database for unambiguous rollback test')
        db=dbs[0];snapshots=[]
        for a in (self.a,self.b):
            snap=self.scratch/('snapshot-'+secrets.token_hex(8)+'.sqlite')
            src=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True);dst=sqlite3.connect(snap)
            try:src.backup(dst)
            finally:dst.close();src.close()
            snapshots.append(snap);self.call(s,'revoke',actor=a)
        self.deny(self.req(s,self.a,self.x));self.deny(self.req(s,self.b,self.y))
        anchors=[p for p in self.files(s) if p.name in ('.cluster_epoch_anchor','external_checkpoints.json')]
        if not anchors:raise Skip('no independent current anchor available; rollback threat model unclear')
        # Replace only the database for each successive rollback attempt. External state is not restored.
        for snap in reversed(snapshots):
            for ext in ('-wal','-shm','-journal'):
                p=Path(str(db)+ext)
                if p.exists():p.unlink()
            shutil.copyfile(snap,db)
            for a,x in ((self.a,self.x),(self.b,self.y)):
                self.reject_raw(s,'read',actor=a,asset=x,request_id=secrets.token_hex(12))

    def test_web_boundaries(self):
        # ASGI in-process transport, no sockets, no external targets. Copy only source.
        s=self.state();copy=self.scratch/('web-source-'+secrets.token_hex(8));copy.mkdir()
        pkg=self.root/'quantumvault'
        if not (pkg/'web'/'app.py').is_file():raise Skip('web module not present')
        shutil.copytree(pkg,copy/'quantumvault',ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.sqlite*','*.db','*.key','.env*','*.pem','*.p12','*.log'),symlinks=True)
        # Reject symlinks rather than accidentally reading source outside the disposable tree.
        if any(p.is_symlink() for p in (copy/'quantumvault').rglob('*')):raise Skip('web source copy contains symlinks')
        p=subprocess.run([sys.executable,'-c',WEB_PROBE,str(copy)],cwd=s,env=self.env(s),capture_output=True,timeout=30)
        if p.returncode:raise Skip('isolated ASGI startup failed; actual web dependencies/configuration needed')
        try:r=json.loads(p.stdout.decode().splitlines()[-1])
        except (ValueError,IndexError):raise Skip('ASGI probe did not return status evidence') from None
        if 'skip' in r:raise Skip(r['skip'])
        status=r['statuses'];self.observations.append(dict(test='web-status',statuses=status))
        if status['baseline']>=500:raise Skip('web startup/root unhealthy; negative probes not conclusive')
        require(status['bad_host'] in (400,403,421),'untrusted Host header not blocked')
        for k in ('rotate_no_token','logout_no_token','rotate_bad_token','rotate_bad_origin'):
            if status[k] in (404,405):raise Skip('documented web route absent or changed: '+k)
            require(status[k] in (400,401,403),'unauthorized operator mutation not rejected: '+k+' HTTP '+str(status[k]))


def self_test():
    def tr(state,h):
        if h['op']=='revoke':return True
        return state if h['allowed']==(not state) else None
    # Overlapping allow and revoke can be valid; post-ack allow is impossible.
    good=[dict(op='revoke',start=1,end=4),dict(op='read',start=2,end=5,allowed=True)]
    bad=[dict(op='revoke',start=1,end=2),dict(op='read',start=3,end=4,allowed=True)]
    assert linearizable(False,good,tr)==(1,0)
    assert linearizable(False,bad,tr) is None
    assert linearizable(False,[dict(op='read',start=1,end=2,allowed=False)],tr) is None
    print('SELF-TEST PASS: valid overlapping history, impossible post-ack allow, impossible initial deny')


def main():
    ap=argparse.ArgumentParser(description='QuantumVault V4 — bounded concurrent-history and crash-boundary challenge; owned repository only')
    ap.add_argument('--repo',type=Path,default=Path('.'));ap.add_argument('--seed',type=int,default=41127)
    ap.add_argument('--rounds',type=int,default=4,choices=range(1,9),metavar='1..8',help='bounded history repetitions')
    ap.add_argument('--report',type=Path,default=Path('challenge-u-to-break-v4-results.json'))
    ap.add_argument('--only',help='filter test name (case insensitive)');ap.add_argument('--extended',action='store_true',help='also run 16 additional V3 groups, 20 earlier groups and project-owned regression suite')
    ap.add_argument('--self-test',action='store_true',help='test history checker without the repository')
    args=ap.parse_args()
    if args.self_test:self_test();return 0
    root=args.repo.resolve()
    if not (root/'track4_service.py').is_file():ap.error('point --repo to your own QuantumVault checkout')
    if args.report.exists():ap.error('report already exists; use a new --report filename')
    with tempfile.TemporaryDirectory(prefix='qv-v4-local-') as tmp:
        c=V4(root,Path(tmp),args.seed,rounds=args.rounds)
        tests=[('Linearizability: concurrent reads and revocations','hardening',c.test_linear_revoke),('Linearizability: competing setup generations and reads','hardening',c.test_linear_generations),('Linearizability: concurrent ML-KEM proofs and revocation','hardening',c.test_linear_kem),('Post-COMMIT kill: durable revocation','resilience',c.test_postcommit_revoke),('Post-COMMIT kill: durable setup generation','resilience',c.test_postcommit_setup),('Pre-COMMIT kill: revocation','resilience',c.deterministic_revoke_crash),('Pre-COMMIT kill: setup','resilience',c.deterministic_setup_crash),('Brief SQLite writer contention','resilience',c.test_write_lock),('Project input cap and oversized reset','hardening',c.test_wire_limits),('Malformed setup transactional preservation','hardening',c.test_malformed_state),('Historical audit IDs under replay pressure','hardening',c.test_audit_history_pressure),('Repeated KEM challenges across setup generations','contract',c.test_kem_multi_generation),('Multi-generation DB-only rollback with current anchors','threat-model',c.test_multi_snapshot),('Local ASGI Host and operator mutation authorization','web-hardening',c.test_web_boundaries)]
        if args.extended:
            tests += [('V3 uninitialized state','contract',c.no_init),('V3 embedded NUL IDs','contract',c.opaque_nul),('V3 selective revocation','contract',c.multiple_assets),('V3 reset generation','contract',c.reset_generation),('V3 near-limit Unicode','contract',c.large_unicode),('V3 temp fallback','contract',c.fallback_temp),('V3 conflicting audit ID','hardening',c.parallel_collision),('V3 KEM revocation race','contract',c.protected_revoke_race),('V3 noncanonical ML-KEM key','hardening',c.pqc_canonical_key),('V3 cross-owner ciphertext swap','storage',c.cross_owner_swap),('V3 same-owner ciphertext swap','storage',c.same_owner_swap),('V3 nonce uniqueness','storage',c.nonce_uniqueness),('V3 anchor corruption','hardening',c.anchor_corruption),('V3 database-only rollback','threat-model',c.db_only_rollback),('V3 concurrent setups','hardening',c.concurrent_setup_snapshot),('V3 randomized oracle','contract',c.multiseed_oracle),('Earlier ownership matrix','contract',c.ownership),('Earlier persistent revocation','contract',c.revoke),('Earlier state isolation','contract',c.isolation),('Earlier duplicate after revocation','hardening',c.duplicate_id),('Earlier opaque identifiers','contract',c.opaque),('Earlier malformed input','hardening',c.malformed),('Earlier independent KEM','contract',c.pqc),('Earlier malformed KEM keys','hardening',c.bad_keys),('Earlier read revoke race','hardening',c.race),('Earlier parser failure atomicity','hardening',c.parser_atomicity),('Earlier Unicode normalization','contract',c.normalization),('Earlier conflicting audit IDs','hardening',c.audit_collision),('Earlier parallel revocations','hardening',c.parallel_revocations),('Earlier KEM binding','contract',c.pqc_binding),('Earlier disk plaintext','storage',c.disk_plaintext),('Earlier SQLite integrity','storage',c.sqlite_integrity),('Earlier ciphertext corruption','storage',c.ciphertext_corruption),('Earlier timing-based exit','resilience',c.abrupt_exit),('Earlier cross-state KEM','contract',c.cross_state_key_binding),('Earlier historical oracle','contract',c.random_deep),('Project-owned regression suite','project-owned',c.extended)]
        selected=[t for t in tests if not args.only or args.only.casefold() in t[0].casefold()]
        if not selected:ap.error('no matching tests')
        for n,k,f in selected:c.run(n,k,f)
        counts={k:sum(r['status']==k for r in c.results) for k in ('PASS','FAIL','ERROR','SKIP')}
        report=dict(version=4,seed=args.seed,rounds=args.rounds,adapter_calls=c.calls,counts=counts,results=c.results,observations=c.observations,limitations=['Only completed bounded histories checked; not a formal proof of linearizability. Concurrent setup semantics are an extra hardening expectation.','SQLite hooks cover observed explicit SQL/connection commit boundaries, not power loss or every code path. Input cap test checks the project-reported input policy, not a confirmed official stdin limit.','Database-only rollback assumes an independent trusted anchor; direct tampering may exceed organizer contract.','Web probe uses copied source, ASGI in-process transport and documented routes; not full authenticated web/session testing.','No direct source-specific IPC, recovery, outbox or messaging protocol tests without confirmed interfaces.','The project-owned suite is opt-in and not independent evidence.','No external requests; do not run against others or real state.','Random selection seed is repeatable, but synthetic secrets and OS scheduling are not.'])
        with args.report.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print('SUMMARY',counts,'| adapter calls:',c.calls,'| report:',args.report)
        return 1 if counts['FAIL'] or counts['ERROR'] else 2 if counts['SKIP'] else 0

# V5 additions. V4 is embedded for the standalone --extended option.
import csv, inspect, datetime, contextlib

PROBE5 = r'''
import sys, os, json, inspect, importlib, sqlite3, csv, copy, datetime, secrets, dataclasses
from pathlib import Path
sys.path.insert(0,sys.argv[1]); root=Path(sys.argv[1]); state=Path(sys.argv[2]); kind=sys.argv[3]
class Skip(Exception):pass
class Finding(Exception):pass
def need(ok,msg):
    if not ok:raise Finding(msg)
def sig(fn):return inspect.signature(fn)
def invoke(fn, values):
    args=[]; kw={}
    for p in sig(fn).parameters.values():
        if p.kind in (p.VAR_POSITIONAL,p.VAR_KEYWORD):continue
        if p.name in values:
            if p.kind==p.POSITIONAL_ONLY:args.append(values[p.name])
            else:kw[p.name]=values[p.name]
        elif p.default is p.empty:raise Skip('unsupported required parameter: '+p.name)
    return fn(*args,**kw)
def module(n):
    try:return importlib.import_module(n)
    except ImportError:raise Skip('module/dependency unavailable: '+n) from None
def mapping(x):
    if isinstance(x,dict):return x
    if dataclasses.is_dataclass(x):return dataclasses.asdict(x)
    if hasattr(x,'model_dump'):return x.model_dump()
    if hasattr(x,'__dict__'):return vars(x)
    return {}
def pick(d,*keys):
    for k in keys:
        if k in d:return d[k]
    return None

def replay():
    m=module('quantumvault.messaging.replay')
    # Only exercise unambiguous public single-sequence window interfaces.
    cls=next((getattr(m,n) for n in ('ReplayWindow','SlidingReplayWindow','SlidingWindow','SlidingWindowReplayProtection','ReplayProtector','ReplayProtection','ReplayGuard') if inspect.isclass(getattr(m,n,None))),None)
    if cls is None:raise Skip('no recognized replay-window class')
    vals={'window_size':64,'size':64,'window':64,'window_bits':64}
    try:w=invoke(cls,vals)
    except Skip:raise
    fn=next((getattr(w,n) for n in ('check_and_mark','check_and_accept','accept','check_and_record','check_and_update') if callable(getattr(w,n,None))),None)
    if fn is None:raise Skip('no recognized single-sequence replay method')
    def call(seq):
        try:r=invoke(fn,{'seq':seq,'sequence':seq,'sequence_number':seq,'seq_num':seq,'seq_no':seq})
        except Exception as e:
            if isinstance(e,Skip):raise
            if type(e).__name__ in ('SecurityPolicyError','ReplayError','ValueError','CryptoError'):return False
            raise
        if type(r) is not bool:raise Skip('replay method does not expose boolean acceptance')
        return r
    if not call(100):raise Skip('initial sequence not accepted; window initialization differs')
    need(not call(100),'same sequence accepted twice')
    need(call(102),'valid newer sequence rejected')
    need(call(101),'valid reordered unseen sequence rejected')
    need(not call(101),'reordered duplicate accepted')
    need(call(164),'valid advance by 62 rejected')
    need(not call(100),'sequence outside 64-entry window accepted')
    need(not call(101),'stale sequence accepted after window advance')
    need(call(163),'unseen sequence inside current window rejected')
    need(not call(163),'duplicate inside window accepted')
    return {'interface':cls.__name__+'.'+fn.__name__,'checks':10}

def predictions(result):
    # Require actual per-event predictions, never infer them from accuracy or labels.
    if isinstance(result,(tuple,list)):
        if result and all(isinstance(mapping(x),dict) and pick(mapping(x),'event_id','id') is not None for x in result):
            rows=result
        else:
            for x in result:
                try:return predictions(x)
                except Skip:pass
            raise Skip('no per-event predictions in evaluator result')
    else:
        d=mapping(result); rows=pick(d,'predictions','event_predictions','classifications','results','event_results','details')
        if isinstance(rows,dict):
            out={}
            for k,v in rows.items():
                label=v if isinstance(v,str) else pick(mapping(v),'predicted_label','prediction','classification','predicted','label')
                if isinstance(label,str):out[str(k)]=label
            if out:return out
        if rows is None:raise Skip('evaluator does not expose predictions')
    if not isinstance(rows,(tuple,list)):raise Skip('prediction format unsupported')
    out={}
    for x in rows:
        d=mapping(x); i=pick(d,'event_id','id'); label=pick(d,'predicted_label','prediction','classification','predicted')
        if i is not None and isinstance(label,str):
            need(str(i) not in out,'duplicate prediction for a single event ID');out[str(i)]=label
    if not out:raise Skip('per-event output schema unsupported')
    return out

def detection():
    m=module('quantumvault.detection.evaluator')
    prac=root/'references'/'track4-toolkit'/'practice'
    if not all((prac/n).is_file() for n in ('events.csv','labels.csv','approvals.json')):raise Skip('official practice fixtures unavailable in copied repository')
    with (prac/'events.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f));fields=list(rows[0]) if rows else []
    with (prac/'labels.csv').open(encoding='utf-8-sig',newline='') as f:labels=list(csv.DictReader(f));lf=list(labels[0]) if labels else []
    approvals=json.loads((prac/'approvals.json').read_text(encoding='utf-8-sig'))
    if 'event_id' not in fields or 'event_id' not in lf:raise Skip('practice schema not recognized')
    labelcol=next((k for k in ('label','expected_label','classification','ground_truth') if k in lf),None)
    if not labelcol:raise Skip('ground truth label column unavailable')
    candidates=[]
    for name in ('evaluate_practice_dataset','evaluate_dataset','evaluate','run_evaluation','evaluate_practice','evaluate_from_files','evaluate_csv'):
        fn=getattr(m,name,None)
        if callable(fn) and not inspect.isclass(fn):candidates.append(fn)
    # Only explicitly named path arguments; never invoke an unknown no-argument evaluator.
    def aliases(folder):
        ev=folder/'events.csv';la=folder/'labels.csv';ap=folder/'approvals.json'
        v={}
        for p,ns in ((ev,('events_path','event_path','events_csv','events_file','events_csv_path','event_file','event_csv_path')),(la,('labels_path','label_path','labels_csv','labels_file','labels_csv_path','label_file')),(ap,('approvals_path','approval_path','approvals_json','approvals_file','approvals_json_path','approval_file'))):
            for n in ns:v[n]=str(p)
        for n in ('practice_dir','dataset_dir','data_dir','directory','fixture_dir'):v[n]=str(folder)
        return v
    def write(folder,rs,ls,aps):
        folder.mkdir()
        for name,fr,data in [('events.csv',fields,rs),('labels.csv',lf,ls)]:
            with (folder/name).open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=fr);w.writeheader();w.writerows(data)
        (folder/'approvals.json').write_text(json.dumps(aps),encoding='utf-8')
    base=state/'baseline';write(base,rows,labels,approvals)
    chosen=None; baseline=None
    for fn in candidates:
        names=set(sig(fn).parameters); vals=aliases(base)
        if not names.intersection(vals):continue
        try:baseline=predictions(invoke(fn,vals));chosen=fn;break
        except (Skip,TypeError,AttributeError):continue
    if chosen is None:raise Skip('no compatible evaluator exposing per-event predictions; need actual detection API')
    expected={r['event_id']:r[labelcol] for r in labels}
    if set(baseline)!=set(expected):raise Skip('baseline evaluator output does not cover the practice event IDs')
    need(baseline==expected,'baseline classifications differ from independently read public labels')
    def evaluate(folder,rs,ls,aps):
        write(folder,rs,ls,aps);return predictions(invoke(chosen,aliases(folder)))
    if kind=='detection-labels':
        # Reverse the ground-truth labels, not the inputs. Predictions must not change.
        bad=[dict(r) for r in labels];values=[r[labelcol] for r in bad];values=values[1:]+values[:1]
        for r,v in zip(bad,values):r[labelcol]=v
        need(any(r[labelcol]!=o[labelcol] for r,o in zip(bad,labels)),'label mutation ineffective')
        out=evaluate(state/'changed_labels',rows,bad,approvals)
        need(out==baseline,'predictions changed when only evaluation labels changed')
    elif kind=='detection-ids':
        ids={r['event_id']:'qv-'+secrets.token_hex(12) for r in rows}
        rs=[dict(r,event_id=ids[r['event_id']]) for r in rows];ls=[dict(r,event_id=ids[r['event_id']]) for r in labels]
        out=evaluate(state/'renamed',rs,ls,approvals)
        need(out=={ids[k]:v for k,v in baseline.items()},'opaque event-ID renaming changed classification')
    elif kind=='detection-time':
        # Translate every UTC timestamp, including approval validity windows, by the same interval.
        def shift(v):
            if isinstance(v,list):return [shift(x) for x in v]
            if isinstance(v,dict):return {k:shift(x) for k,x in v.items()}
            if isinstance(v,str) and len(v)>=20 and v[4:5]=='-' and 'T' in v and (v.endswith('Z') or v.endswith('+00:00')):
                try:return (datetime.datetime.fromisoformat(v.replace('Z','+00:00'))+datetime.timedelta(days=37)).isoformat(timespec='milliseconds').replace('+00:00','Z')
                except ValueError:pass
            return v
        rs=shift(rows);aps=shift(approvals)
        need(rs!=rows and aps!=approvals,'timestamp shift did not affect both fixtures')
        out=evaluate(state/'shifted',rs,labels,aps)
        need(out==baseline,'uniform event/approval time translation changed classifications')
    elif kind=='detection-duplicate':
        # Exact duplicate events must not invent additional incident evidence or predictions.
        # Prediction extraction rejects duplicates explicitly.
        rs=rows[:6]+[dict(rows[4])]+rows[6:]
        try:out=evaluate(state/'duplicate',rs,labels,approvals)
        except (ValueError,TypeError) as e:raise Skip('evaluator rejects duplicates; ingestion policy must be inspected') from None
        need(out==baseline,'identical duplicate changed unrelated classifications')
    return {'interface':chosen.__name__,'baseline_events':len(baseline),'transformation':kind}

def web():
    m=module('quantumvault.web.app'); auth=module('quantumvault.web.authentication')
    try:from fastapi.testclient import TestClient
    except ImportError:raise Skip('FastAPI TestClient unavailable') from None
    app=getattr(m,'app',None)
    if app is None:raise Skip('ASGI app not exported')
    def token():
        # Explicit runtime token getter only. Never read the original repo or environment credentials.
        for obj in (auth,m,getattr(app,'state',None)):
            if obj is None:continue
            for name in ('get_operator_token','get_current_operator_token','current_operator_token','operator_token','OPERATOR_TOKEN','_operator_token'):
                v=getattr(obj,name,None)
                if callable(v):
                    try:v=invoke(v,{})
                    except Skip:continue
                if isinstance(v,str) and len(v)>=16:return v
        return None
    try:client=TestClient(app,base_url='http://localhost:8000',raise_server_exceptions=False)
    except TypeError:raise Skip('incompatible ASGI client') from None
    with client:
        old=token()
        if old is None:raise Skip('no recognized runtime token accessor')
        path='/api/v1/auth/rotate'; logout='/api/v1/auth/logout'
        headers={'X-Operator-Token':old,'Origin':'http://localhost:8000'}
        if kind=='web-origin':
            r=client.post(path,headers=dict(headers,Origin='http://untrusted.invalid'))
            if r.status_code in (404,405):raise Skip('rotation route absent')
            need(r.status_code in (400,401,403,421),'valid token accepted with untrusted Origin')
            need(token()==old,'rejected origin mutated operator token')
            r=client.post(path,headers=headers)
            if not 200<=r.status_code<300:raise Skip('positive token/origin control not accepted')
            need(token()!=old,'successful rotation did not change runtime token')
        else:
            r=client.post(path,headers=headers)
            if not 200<=r.status_code<300:raise Skip('positive authenticated rotate control failed')
            new=token()
            need(isinstance(new,str) and new!=old,'successful rotate did not replace runtime token')
            r=client.post(path,headers=headers)
            need(r.status_code in (400,401,403),'old token accepted after rotation')
            need(token()==new,'rejected old token mutated active token')
            r=client.post(logout,headers=dict(headers,**{'X-Operator-Token':new}))
            if r.status_code in (404,405):raise Skip('logout route absent')
            if not 200<=r.status_code<300:raise Skip('positive logout control not accepted')
            r=client.post(path,headers=dict(headers,**{'X-Operator-Token':new}))
            need(r.status_code in (400,401,403),'logged-out token accepted by rotation endpoint')
        return {'positive_control':True,'interface':'local ASGI only'}

def find_database():
    dbs=[]
    for p in state.rglob('*'):
        if p.is_file() and not p.is_symlink():
            try:
                with p.open('rb') as f:
                    if f.read(16)==b'SQLite format 3\x00':dbs.append(p)
            except OSError:pass
    if len(dbs)!=1:raise Skip('internal probe requires one initialized SQLite database')
    return dbs[0]
def db_connection(path):
    conn=sqlite3.connect(path,timeout=5,isolation_level=None);conn.row_factory=sqlite3.Row;conn.execute('PRAGMA foreign_keys=ON');return conn
def db_values(path,conn):
    return {'conn':conn,'connection':conn,'db_conn':conn,'db_connection':conn,'db_path':path,'database_path':path,'state_dir':state,'state_path':state}
def recovery():
    import concurrent.futures, threading
    m=module('quantumvault.iam.recovery');cls=getattr(m,'RecoveryManager',None)
    if not inspect.isclass(cls):raise Skip('RecoveryManager interface unavailable')
    path=find_database();actor=os.environ['QV5_TEST_ACTOR']
    def manager(conn):return invoke(cls,db_values(path,conn))
    with __import__('contextlib').closing(db_connection(path)) as conn:
        mgr=manager(conn)
        gen=next((getattr(mgr,n) for n in ('generate_codes','generate_recovery_codes','create_recovery_codes','generate') if callable(getattr(mgr,n,None))),None)
        if gen is None:raise Skip('recognized recovery-code generator unavailable')
        identity={n:actor for n in ('actor','actor_id','identity','identity_id','user_id','account_id','username')}
        raw=invoke(gen,dict(identity,count=3,num_codes=3,n=3,quantity=3))
        if isinstance(raw,dict):raw=pick(raw,'codes','recovery_codes')
        if not isinstance(raw,(list,tuple)) or len(raw)<2 or not all(isinstance(c,str) for c in raw):raise Skip('recovery generator does not return a recognized code list')
        codes=list(raw)
    def consume(code,barrier=None):
        with __import__('contextlib').closing(db_connection(path)) as conn:
            mgr=manager(conn);fn=getattr(mgr,'verify_and_consume',None)
            if not callable(fn):raise Skip('verify_and_consume unavailable')
            if barrier:barrier.wait(timeout=5)
            try:val=invoke(fn,dict(identity,code=code,recovery_code=code,credential=code))
            except Exception as e:
                if isinstance(e,Skip):raise
                if type(e).__name__ in ('SecurityPolicyError','AuthenticationError','AuthorizationError','RecoveryError','CryptoError','ValueError','StateError'):return False
                raise
            if isinstance(val,bool):return val
            if isinstance(val,dict) and type(pick(val,'success','valid','accepted')) is bool:return pick(val,'success','valid','accepted')
            if val is None:return False
            raise Skip('recovery verifier result not an explicit success/denial')
    if not consume(codes[0]):raise Skip('valid recovery-code positive control failed or returns unsupported success type')
    need(not consume(codes[0]),'consumed recovery code accepted again from a new connection')
    barrier=threading.Barrier(2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(consume,codes[1],barrier) for _ in range(2)];out=[f.result(timeout=15) for f in futures]
    need(sum(out)==1,'same recovery code did not produce exactly one successful consumption across separate connections')
    need(not consume(codes[1]),'raced recovery code accepted again')
    return {'interface':'RecoveryManager.verify_and_consume','separate_connections':2,'successful_race_consumptions':sum(out)}

def audit_verify():
    path=find_database();m=module('quantumvault.audit.verifier');cls=getattr(m,'AuditLogVerifier',None)
    if not inspect.isclass(cls):raise Skip('AuditLogVerifier class unavailable')
    def verify():
        with __import__('contextlib').closing(db_connection(path)) as conn:
            vals=db_values(path,conn)
            obj=invoke(cls,vals)
            fn=next((getattr(obj,n) for n in ('verify','verify_chain','verify_log','verify_all','verify_integrity','verify_audit_log') if callable(getattr(obj,n,None))),None)
            if fn is None:raise Skip('recognized audit verification method unavailable')
            r=invoke(fn,vals)
            if type(r) is bool:return r
            d=mapping(r);v=pick(d,'valid','is_valid','integrity_valid','verified','ok')
            if type(v) is bool:return v
            status=pick(d,'status','integrity_status')
            if isinstance(status,str):
                if status.lower() in ('valid','verified','ok','pass','intact'):return True
                if status.lower() in ('tampered','invalid','failed','fail','corrupt','corrupted','truncated'):return False
            raise Skip('audit verifier does not expose a recognized validity result')
    if not verify():raise Skip('valid audit positive control failed; checkpoint setup or verifier interface needs inspection')
    rid=os.environ['QV5_TEST_RID'];changed=False
    with __import__('contextlib').closing(db_connection(path)) as conn:
        for table in ('audit_events','audit_log','audit_logs','audit_entries'):
            cols={r[1] for r in conn.execute(f'PRAGMA table_info({table})')}
            if {'request_id','decision'}<=cols:
                changed=conn.execute(f'UPDATE {table} SET decision=? WHERE request_id=?',('deny',rid)).rowcount>0
                if changed:break
    if not changed:raise Skip('audit schema does not expose request ID and decision columns')
    need(not verify(),'independent audit verifier accepted altered decision')
    return {'positive_control':True,'tamper_detected':True}

try:
    if kind.startswith('detection-'):result=detection()
    elif kind.startswith('web-'):result=web()
    elif kind=='replay-window':result=replay()
    elif kind=='recovery-race':result=recovery()
    elif kind=='audit-verifier':result=audit_verify()
    else:raise Skip('unsupported probe')
    output={'status':'PASS','observation':result}
except Skip as e:output={'status':'SKIP','detail':str(e)}
except Finding as e:output={'status':'FAIL','detail':str(e)}
except Exception as e:output={'status':'ERROR','detail':type(e).__name__+' (inspect local interface; details omitted)'}
print('QV5_RESULT '+json.dumps(output))
'''

class V5(V4):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw)
        self.case_count=0

    def wire(self,s,payload):
        p=self.raw(s,payload);require(p.returncode==0,'valid alternate JSON encoding rejected')
        try:r=strict_json(p.stdout.decode('utf-8'))
        except (ValueError,UnicodeError):raise Finding('alternate JSON encoding produced invalid response') from None
        require(isinstance(r,dict),'alternate JSON response not object');return r

    def test_json_metamorphic(self):
        s=self.state();self.setup(s)
        for ascii_only,indent,reverse in ((True,None,False),(False,2,True),(True,4,True),(False,None,False)):
            r={'op':'read','actor':self.a,'asset':self.x,'request_id':secrets.token_hex(12)+'é🔐'}
            pairs=list(r.items());self.rng.shuffle(pairs)
            if reverse:pairs.reverse()
            self.allow(self.wire(s,('\n\t'+json.dumps(dict(pairs),ensure_ascii=ascii_only,indent=indent)+'\r\n').encode()),self.body)
            self.audit(s,r['request_id'],'allow')
        self.call(s,'revoke',actor=self.a)
        self.deny(self.wire(s,json.dumps(dict(request_id='post-'+secrets.token_hex(8),asset=self.x,actor=self.a,op='read'),indent=2).encode()))

    def test_actor_renaming(self):
        # Bijection between opaque identifiers. Independent expected authorization matrix.
        names=['a-'+secrets.token_hex(6),'A-'+secrets.token_hex(6),'名-'+secrets.token_hex(6)]
        for generation in range(2):
            s=self.state();actors=names if generation==0 else ['𝄞:'+secrets.token_hex(8),'\tκ:'+secrets.token_hex(8),'é:'+secrets.token_hex(8)]
            assets=['doc:'+secrets.token_hex(7) for _ in actors];bodies=[self.body,self.peer,self.disabled_body]
            self.setup_map(s,dict(zip(assets,actors)),dict(zip(assets,bodies)),disabled=[actors[2]])
            for i,a in enumerate(actors):
                for j,x in enumerate(assets):
                    r=self.req(s,a,x)
                    if i==j and i<2:self.allow(r,bodies[j])
                    else:self.deny(r)
            self.call(s,'revoke',actor=actors[0]);self.deny(self.req(s,actors[0],assets[0]));self.allow(self.req(s,actors[1],assets[1]),bodies[1])

    def test_object_key_permutation(self):
        s=self.state();items=[(self.x,self.a,self.body),(self.y,self.b,self.peer),(self.z,self.c,self.disabled_body)]
        for _ in range(3):
            self.rng.shuffle(items);own={x:a for x,a,b in items};order=items[:];self.rng.shuffle(order);body={x:b for x,a,b in order}
            self.setup_map(s,own,body,[self.c]);self.allow(self.req(s,self.a,self.x),self.body);self.allow(self.req(s,self.b,self.y),self.peer);self.deny(self.req(s,self.c,self.z))

    def test_literal_data(self):
        s=self.state();body=self.body+'\x00\u2028\u2029\ufeff\u202e\n{"op":"revoke","actor":"fake"}\r\n'+self.peer+'\n'
        self.setup_map(s,{self.x:self.a},{self.x:body});r=self.req(s,self.a,self.x)
        require(r=={'decision':'allow','body':body},'literal content changed or interpreted as commands')
        self.deny(self.req(s,self.b,self.x));self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))

    def test_invalid_utf8_atomicity(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a)
        base=json.dumps(dict(op='setup',owners={self.x:self.a},contents={self.x:'REPLACE'},disabled=[],key_material=self.marker)).encode()
        for invalid in (b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82'):
            self.no_disclosure(self.raw(s,base.replace(b'REPLACE',invalid)));self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def test_malformed_revoke_types(self):
        s=self.state();self.setup(s)
        for a in (None,False,0,[self.a],{'actor':self.a}):
            p=self.raw(s,json.dumps(dict(op='revoke',actor=a)).encode())
            # Invalid revocation may return a sanitized error or no-op, but must not revoke a valid actor.
            require(self.marker.encode() not in p.stdout+p.stderr,'key leaked');self.allow(self.req(s,self.a,self.x),self.body);self.allow(self.req(s,self.b,self.y),self.peer)
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))

    def test_partial_kem_coefficients(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair();ch='coeff-'+secrets.token_hex(8)
        # FIPS 203 canonical encoding: each packed 12-bit coefficient must be < q=3329.
        # Change individual coefficients in different polynomial positions, preserve length and other bytes.
        for index,value in ((0,3329),(1,4095),(255,3329),(512,4095),(767,3329)):
            k=bytearray(pk);off=(index//2)*3
            if index%2:k[off+1]=(k[off+1]&15)|((value&15)<<4);k[off+2]=value>>4
            else:k[off]=value&255;k[off+1]=(k[off+1]&240)|(value>>8)
            self.reject_raw(s,'protected_read',actor=self.a,asset=self.x,challenge=ch,public_key=base64.b64encode(k).decode())
        r=self.call(s,'protected_read',actor=self.a,asset=self.x,challenge=ch,public_key=base64.b64encode(pk).decode());ct=base64.b64decode(r['ciphertext'],validate=True)
        require(hmac.compare_digest(r['proof'],hmac.new(kem.decrypt(sk,ct),(ch+self.body).encode(),hashlib.sha256).hexdigest()),'valid key positive control failed')

    def test_database_fork(self):
        # Fork a complete disposable state at a quiescent boundary. Revoking one branch must not affect another.
        s=self.state();self.setup(s);self.allow(self.req(s,self.a,self.x),self.body)
        t=self.state();shutil.copytree(s,t,dirs_exist_ok=True)
        self.call(s,'revoke',actor=self.a);self.call(t,'revoke',actor=self.b)
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
        self.allow(self.req(t,self.a,self.x),self.body);self.deny(self.req(t,self.b,self.y))
        self.check_db(s);self.check_db(t)

    def test_read_snapshot(self):
        s=self.state();self.setup(s);dbs=self.databases(s)
        if len(dbs)!=1:raise Skip('single SQLite database required')
        db=sqlite3.connect(dbs[0],timeout=2,isolation_level=None)
        try:
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower()!='wal':raise Skip('WAL snapshot test requires WAL mode')
            db.execute('BEGIN');db.execute('SELECT count(*) FROM sqlite_master').fetchone()
            # Old read-only SQLite snapshot must not make newly invoked adapter use obsolete permissions.
            self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
        finally:db.close()
        self.deny(self.req(s,self.a,self.x));self.check_db(s)

    def test_asset_owner_metadata(self):
        s=self.state();self.setup(s);changed=False
        for p in self.databases(s):
            with contextlib.closing(sqlite3.connect(p,timeout=3)) as db:
                cols={r[1] for r in db.execute('PRAGMA table_info(assets)')};ident=next((x for x in ('asset_id','id','resource_id') if x in cols),None);owner=next((x for x in ('owner_id','owner','actor_id','owner_actor_id') if x in cols),None)
                if not ident or not owner:continue
                with db:changed=db.execute(f'UPDATE assets SET "{owner}"=? WHERE "{ident}"=?',(self.b,self.x)).rowcount==1
                if changed:break
        if not changed:raise Skip('asset owner schema not recognized')
        # Changing ownership metadata alone must not defeat owner-bound AEAD.
        self.reject_raw(s,'read',actor=self.b,asset=self.x,request_id=secrets.token_hex(12));self.allow(self.req(s,self.b,self.y),self.peer)

    def test_proof_opaque_key(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();body='x\x00é\r\n🔐'+self.body;self.setup_map(s,{self.x:self.a},{self.x:body});pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode()
        for ch in ('','\x00','e\u0301','é','\r\n','🔐\u2028'):
            p=self.raw(s,json.dumps(dict(op='protected_read',actor=self.a,asset=self.x,challenge=ch,public_key=pub),ensure_ascii=True).encode())
            if not ch and p.returncode!=0:continue # empty challenge may be excluded by contract
            if not ch:
                try:r=strict_json(p.stdout.decode())
                except ValueError:continue
                if r.get('decision')=='deny':continue
            else:
                require(p.returncode==0,'valid Unicode challenge rejected');r=strict_json(p.stdout.decode())
            require(set(r)=={'ciphertext','proof'},'proof shape wrong for opaque challenge');ct=base64.b64decode(r['ciphertext'],validate=True);ss=kem.decrypt(sk,ct)
            require(hmac.compare_digest(r['proof'],hmac.new(ss,(ch+body).encode(),hashlib.sha256).hexdigest()),'challenge/body byte binding failed')

    def test_distinct_state_parallel(self):
        pairs=[]
        for i in range(3):
            s=self.state();b='QV_PARALLEL_'+secrets.token_hex(20);self.setup_map(s,{self.x:self.a},{self.x:b});pairs.append((s,b))
        def worker(item):
            s,b=item;self.allow(self.req(s,self.a,self.x),b);self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:list(ex.map(worker,pairs[:2]))
        self.allow(self.req(pairs[2][0],self.a,self.x),pairs[2][1]);self.deny(self.req(pairs[2][0],self.b,self.x))

    def probe(self,kind):
        s=self.state();env=self.env(s)
        if kind in ('recovery-race','audit-verifier'):
            self.setup(s);env['QV5_TEST_ACTOR']=self.a;rid='audit-'+secrets.token_hex(12);self.allow(self.req(s,self.a,self.x,rid),self.body);env['QV5_TEST_RID']=rid
        p=subprocess.run([sys.executable,'-c',PROBE5,str(self.root),str(s),kind],cwd=s,env=env,capture_output=True,timeout=45)
        lines=[x for x in p.stdout.decode('utf-8',errors='replace').splitlines() if x.startswith('QV5_RESULT ')]
        if p.returncode or len(lines)!=1:raise Skip('isolated internal probe could not start or return structured evidence')
        r=json.loads(lines[0][11:]);status=r.get('status')
        if status=='SKIP':raise Skip(r['detail'])
        if status=='FAIL':raise Finding(r['detail'])
        if status!='PASS':raise RuntimeError('internal probe error: '+r.get('detail','unknown'))
        self.observations.append(dict(test=kind,**r.get('observation',{})))

    def test_audit_field_tamper(self):
        # Public audit retrieval should not silently attest to a modified decision if it claims verification.
        # Audit lookup may intentionally be an unverified query, so this is reported as a separate threat-model expectation.
        s=self.state();self.setup(s);rid='audit-'+secrets.token_hex(12);self.allow(self.req(s,self.a,self.x,rid),self.body);self.audit(s,rid,'allow');changed=False
        for p in self.databases(s):
            with contextlib.closing(sqlite3.connect(p,timeout=3)) as db:
                for table in ('audit_events','audit_log','audit_logs','audit_entries'):
                    cols={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
                    if {'request_id','decision'}<=cols:
                        with db:changed=db.execute(f'UPDATE {table} SET decision=? WHERE request_id=?',('deny',rid)).rowcount>0
                        if changed:break
                if changed:break
        if not changed:raise Skip('audit schema not recognized')
        p=self.raw(s,json.dumps(dict(op='audit',request_id=rid)).encode())
        if p.returncode==0:
            r=strict_json(p.stdout.decode());
            if r.get('decision')=='deny':raise Finding('raw audit query returned tampered historical decision; verify whether contract requires verification on lookup')
        self.allow(self.req(s,self.b,self.y),self.peer)


def copy_source5(src,dst):
    # Copy only executable source and public fixture data, never runtime state, logs, Git or secret files.
    dst.mkdir();require(not (src/'track4_service.py').is_symlink(),'entrypoint symlink not supported');shutil.copy2(src/'track4_service.py',dst/'track4_service.py')
    allowed={'.py','.sql','.html','.css','.js','.svg','.json','.txt','.md','.woff','.woff2'}
    for directory in ('quantumvault','tests','scripts'):
        base=src/directory
        if not base.is_dir():continue
        for p in base.rglob('*'):
            rel=p.relative_to(src)
            if p.is_symlink() or any(x.startswith('.') or x in ('__pycache__','evidence','state','runtime','data','secrets','backups') for x in rel.parts):continue
            if p.is_file() and p.suffix.lower() in allowed and p.stat().st_size<=4*1024*1024:
                # Do not copy arbitrary JSON/TXT runtime outputs. Source packages may have static JSON config.
                if p.suffix.lower() in ('.json','.txt') and any(x in p.stem.lower() for x in ('key','token','credential','secret','checkpoint','result')):continue
                q=dst/rel;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
    for name in ('events.csv','labels.csv','approvals.json','README.md','examples.md'):
        p=src/'references'/'track4-toolkit'/'practice'/name
        if p.is_file() and not p.is_symlink() and p.stat().st_size<=4*1024*1024:
            q=dst/'references'/'track4-toolkit'/'practice'/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
    p=src/'threat-model.json'
    if p.is_file() and not p.is_symlink():shutil.copy2(p,dst/p.name)


def main5():
    ap=argparse.ArgumentParser(description='QuantumVault V5 — diversified local adversarial regression challenge')
    ap.add_argument('--repo',type=Path,default=Path('.'));ap.add_argument('--seed',type=int,default=53127);ap.add_argument('--rounds',type=int,choices=range(1,9),default=4)
    ap.add_argument('--report',type=Path,default=Path('challenge-u-to-break-v5-results.json'));ap.add_argument('--only');ap.add_argument('--extended',action='store_true',help='also run selected earlier V4 model/crash tests');ap.add_argument('--self-test',action='store_true')
    a=ap.parse_args()
    if a.self_test:
        self_test();compile(PROBE5,'<internal-probe>','exec');print('V5 embedded probe syntax PASS');return 0
    root=a.repo.resolve()
    if not (root/'track4_service.py').is_file():ap.error('point --repo at your own repository')
    if a.report.exists():ap.error('report exists; select a new filename')
    with tempfile.TemporaryDirectory(prefix='qv-v5-local-') as tmp:
        scratch=Path(tmp);copy=scratch/'source';copy_source5(root,copy);c=V5(copy,scratch,a.seed,rounds=a.rounds)
        tests=[('JSON metamorphic encoding','contract',c.test_json_metamorphic),('Opaque actor and resource renaming','contract',c.test_actor_renaming),('Independent mapping order permutation','contract',c.test_object_key_permutation),('Literal control and JSON-shaped body','contract',c.test_literal_data),('Invalid UTF-8 reset atomicity','hardening',c.test_invalid_utf8_atomicity),('Wrong-typed revoke isolation','hardening',c.test_malformed_revoke_types),('ML-KEM individual noncanonical coefficient','crypto-hardening',c.test_partial_kem_coefficients),('ML-KEM opaque challenge/body binding','contract',c.test_proof_opaque_key),('Quiescent state fork isolation','hardening',c.test_database_fork),('Live SQLite reader snapshot vs new revocation','resilience',c.test_read_snapshot),('Owner metadata substitution','threat-model',c.test_asset_owner_metadata),('Parallel same IDs across independent states','hardening',c.test_distinct_state_parallel)]
        for k in ('detection-labels','detection-ids','detection-time','detection-duplicate','replay-window','web-origin','web-session','recovery-race','audit-verifier'):
            tests.append((k,'internal-adaptive',lambda k=k:c.probe(k)))
        if a.extended:tests += [('Raw audit lookup after tampering (extra expectation)','threat-model-extra',c.test_audit_field_tamper),('V4 linearizable revoke','hardening',c.test_linear_revoke),('V4 competing generations','hardening',c.test_linear_generations),('V4 KEM concurrent history','hardening',c.test_linear_kem),('V4 pre-commit revoke kill','resilience',c.deterministic_revoke_crash),('V4 post-commit revoke kill','resilience',c.test_postcommit_revoke),('V4 post-commit setup kill','resilience',c.test_postcommit_setup),('V4 multiple generation rollback','threat-model',c.test_multi_snapshot),('V4 ciphertext cross-owner swap','storage',c.cross_owner_swap),('V4 ciphertext same-owner swap','storage',c.same_owner_swap),('V4 external anchor corruption','hardening',c.anchor_corruption)]
        selected=[t for t in tests if not a.only or a.only.casefold() in t[0].casefold()]
        if not selected:ap.error('no matching test names')
        for n,k,f in selected:c.run(n,k,f)
        counts={k:sum(r['status']==k for r in c.results) for k in ('PASS','FAIL','ERROR','SKIP')}
        report=dict(version=5,seed=a.seed,rounds=a.rounds,adapter_calls=c.calls,counts=counts,results=c.results,observations=c.observations,limitations=['All tests target copied source and temporary state; no external URLs or shared services. This is not a hardened OS sandbox for untrusted repositories.','Adaptive internal tests require compatible signatures; SKIP is not PASS.','Audit lookup test is a stricter threat-model expectation: an API may intentionally return unverified data while providing a separate verification interface.','State fork assumes a portable quiescent state directory; a deliberately location-bound state store may reject the copied branch.','Recovery probe requires recognized RecoveryManager interfaces. No independent outbox/backup/IPC protocol coverage without concrete source interfaces.','Only bounded local experiments, not formal security proof; random secrets and OS scheduling vary across seeds.'])
        with a.report.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print('SUMMARY',counts,'| adapter calls:',c.calls,'| report:',a.report)
        return 1 if counts['FAIL'] or counts['ERROR'] else 2 if counts['SKIP'] else 0
if __name__=='__main__':sys.exit(main5())
