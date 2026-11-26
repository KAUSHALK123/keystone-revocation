#!/usr/bin/env python3
"""V6: local synthetic acceptance and resilience checks, not an official judge.
Targets only a user-owned source copy and disposable state. No network scanning.
Python 3.11+. The included v5_engine.py provides adapter and isolation utilities.
"""
import argparse, base64, contextlib, concurrent.futures, hashlib, hmac, json, os
from pathlib import Path
import random, secrets, shutil, sqlite3, subprocess, sys, tempfile, time, threading
import v5_engine as old

# Some internal interfaces are deliberately adaptive. Incompatible interfaces SKIP.
PROBE = old.PROBE5.rsplit('\ntry:\n    if kind.startswith',1)[0]
PROBE += r'''
import random, subprocess, time, contextlib, concurrent.futures

def window_oracle():
    m=module('quantumvault.messaging.replay')
    cls=next((getattr(m,n) for n in ('ReplayWindow','SlidingReplayWindow','SlidingWindow','SlidingWindowReplayProtection','ReplayProtector','ReplayProtection','ReplayGuard') if inspect.isclass(getattr(m,n,None))),None)
    if cls is None:raise Skip('replay class unavailable')
    obj=invoke(cls,dict(window_size=64,size=64,window=64,window_bits=64))
    fn=next((getattr(obj,n) for n in ('check_and_mark','check_and_accept','accept','check_and_record','check_and_update') if callable(getattr(obj,n,None))),None)
    if fn is None:raise Skip('single-sequence replay method unavailable')
    def call(n):
        try:r=invoke(fn,dict(seq=n,sequence=n,sequence_number=n,seq_num=n,seq_no=n))
        except Exception as e:
            if isinstance(e,Skip):raise
            if type(e).__name__ in ('SecurityPolicyError','ReplayError','ValueError','CryptoError'):return False
            raise
        if type(r) is not bool:raise Skip('nonboolean replay interface')
        return r
    if not call(100):raise Skip('initial sequence semantics differ')
    rng=random.Random(int(os.environ['QV6_SEED']));top=100;seen={100};accepted=1;rejected=0
    for i in range(500):
        n=max(0,top+rng.choice([-130,-65,-64,-63,-1,0,1,2,63,64,129,rng.randint(-90,90)]))
        expected=n>top or (n>=top-63 and n not in seen)
        got=call(n)
        need(got==expected,'replay oracle mismatch at step '+str(i)+' sequence '+str(n))
        if expected:
            top=max(top,n);seen={x for x in seen if x>=top-63};seen.add(n);accepted+=1
        else:rejected+=1
    return dict(operations=501,accepted=accepted,rejected=rejected,interface=cls.__name__+'.'+fn.__name__)

def verifier_for(path):
    m=module('quantumvault.audit.verifier');cls=getattr(m,'AuditLogVerifier',None)
    if not inspect.isclass(cls):raise Skip('AuditLogVerifier unavailable')
    with contextlib.closing(db_connection(path)) as conn:
        vals=db_values(path,conn);obj=invoke(cls,vals)
        fn=next((getattr(obj,n) for n in ('verify','verify_chain','verify_log','verify_all','verify_integrity','verify_audit_log') if callable(getattr(obj,n,None))),None)
        if fn is None:raise Skip('no recognized verifier')
        r=invoke(fn,vals)
        if type(r) is bool:return r
        d=mapping(r);v=pick(d,'valid','is_valid','integrity_valid','verified','ok')
        if type(v) is bool:return v
        s=pick(d,'status','integrity_status')
        if isinstance(s,str) and s.lower() in ('valid','verified','ok','pass','intact'):return True
        if isinstance(s,str) and s.lower() in ('tampered','invalid','failed','fail','corrupt','corrupted','truncated'):return False
        raise Skip('unrecognized audit verification result')

def audit_delete():
    path=find_database()
    if not verifier_for(path):raise Skip('clean audit positive control did not verify')
    with contextlib.closing(db_connection(path)) as conn:
        for table in ('audit_events','audit_log','audit_logs','audit_entries'):
            cols={r[1] for r in conn.execute(f'PRAGMA table_info({table})')}
            if 'request_id' not in cols:continue
            ids=[r[0] for r in conn.execute(f'SELECT request_id FROM {table} WHERE request_id LIKE ?',('qv6-audit-%',))]
            if len(ids)<4:continue
            target=os.environ['QV6_AUDIT_MIDDLE'];need(target in ids,'audit fixture missing')
            need(conn.execute(f'DELETE FROM {table} WHERE request_id=?',(target,)).rowcount==1,'audit deletion fixture failed')
            break
        else:raise Skip('recognized audit rows unavailable')
    need(not verifier_for(path),'verifier accepted deletion of a historical audit event')
    return dict(positive_control=True,deleted_events=1)

def backup_probe():
    path=find_database();m=module('quantumvault.backup.backup_manager');restore=module('quantumvault.backup.restore')
    cls=getattr(m,'BackupManager',None);rcls=getattr(restore,'BackupRestoreManager',None)
    if not inspect.isclass(cls):raise Skip('BackupManager unavailable')
    dest=state/'qv6-test.qvbk'
    with contextlib.closing(db_connection(path)) as conn:
        vals=db_values(path,conn);manager=invoke(cls,vals)
        fn=next((getattr(manager,n) for n in ('create_backup','backup','create') if callable(getattr(manager,n,None))),None)
        if fn is None:raise Skip('backup creation interface unavailable')
        aliases={n:dest for n in ('path','backup_path','output_path','destination','destination_path','file_path','target_path','output_file','filename')}
        if not set(sig(fn).parameters).intersection(aliases):raise Skip('backup creation requires an explicit output path')
        result=invoke(fn,dict(vals,**aliases))
        if isinstance(result,bytes) and not dest.exists():dest.write_bytes(result)
        if not dest.is_file():raise Skip('archive not produced at specified destination')
        data=dest.read_bytes()
        if len(data)<32 or len(data)>8*1024*1024:raise Skip('archive size outside bounded probe')
        candidates=[manager]
        if inspect.isclass(rcls):
            try:candidates.append(invoke(rcls,vals))
            except Skip:pass
        verify=next((getattr(o,n) for o in candidates for n in ('verify_backup','validate_backup','verify_archive','validate_archive') if callable(getattr(o,n,None))),None)
        if verify is None:raise Skip('explicit non-restoring backup verifier unavailable')
        def check(p):
            a={k:p for k in aliases};a.update(archive_path=p,source_path=p)
            if not set(sig(verify).parameters).intersection(a):raise Skip('backup verify path parameter unavailable')
            try:r=invoke(verify,dict(vals,**a))
            except Exception as e:
                if isinstance(e,Skip):raise
                if type(e).__name__ in ('CryptoError','StateError','SecurityPolicyError','InvalidTag','ValueError','BackupError'):return False
                raise
            if type(r) is bool:return r
            d=mapping(r);v=pick(d,'valid','verified','ok','success','authenticated')
            if type(v) is bool:return v
            raise Skip('backup verifier result not explicit')
        if not check(dest):raise Skip('valid backup positive control failed')
        mutations=[]
        for idx in sorted({0,8,len(data)//2,len(data)-1}):
            b=bytearray(data);b[idx]^=1;mutations.append(bytes(b))
        mutations.extend([data[:-1],data[:len(data)//2]])
        for i,b in enumerate(mutations):
            p=state/('qv6-damaged-'+str(i)+'.qvbk');p.write_bytes(b);need(not check(p),'backup verifier accepted damaged archive variant '+str(i))
        need(check(dest),'original backup stopped verifying after negative tests')
        return dict(positive_control=True,mutations=len(mutations),archive_bytes=len(data))

def recovery_processes():
    m=module('quantumvault.iam.recovery');cls=getattr(m,'RecoveryManager',None)
    if not inspect.isclass(cls):raise Skip('RecoveryManager unavailable')
    path=find_database();actor=os.environ['QV6_ACTOR']
    identity={n:actor for n in ('actor','actor_id','identity','identity_id','user_id','account_id','username')}
    with contextlib.closing(db_connection(path)) as conn:
        mgr=invoke(cls,db_values(path,conn))
        gen=next((getattr(mgr,n) for n in ('generate_codes','generate_recovery_codes','create_recovery_codes','generate') if callable(getattr(mgr,n,None))),None)
        if gen is None:raise Skip('recovery generator unavailable')
        codes=invoke(gen,dict(identity,count=3,num_codes=3,n=3,quantity=3))
        if isinstance(codes,dict):codes=pick(codes,'codes','recovery_codes')
        if not isinstance(codes,(tuple,list)) or len(codes)<2 or not all(isinstance(c,str) for c in codes):raise Skip('unrecognized recovery codes')
    def collect(p,code):
        out,_=p.communicate(code.encode(),timeout=20)
        lines=[x[11:] for x in out.decode(errors='replace').splitlines() if x.startswith('QV6_WORKER ')]
        if p.returncode or len(lines)!=1:raise Skip('worker did not return structured result')
        r=json.loads(lines[0])
        if 'skip' in r:raise Skip(r['skip'])
        if 'error' in r:raise RuntimeError(r['error'])
        return r['accepted']
    def start(index):
        return subprocess.Popen([sys.executable,sys.argv[0],str(root),str(state),'recovery-worker',str(index)],cwd=state,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def one(code,index):
        (state/('gate-'+str(index))).touch();p=start(index)
        try:return collect(p,code)
        finally:
            if p.poll() is None:p.kill();p.communicate()
    if not one(codes[0],0):raise Skip('positive process recovery control failed')
    need(not one(codes[0],1),'previously consumed code accepted in a fresh process')
    ps=[start(i) for i in (2,3)]
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fs=[pool.submit(collect,p,codes[1]) for p in ps]
            end=time.monotonic()+8
            while time.monotonic()<end and not all((state/('ready-'+str(i))).exists() for i in (2,3)):
                if any(p.poll() is not None for p in ps):break
                time.sleep(.01)
            ready=all((state/('ready-'+str(i))).exists() for i in (2,3))
            for i in (2,3):(state/('gate-'+str(i))).touch()
            outcomes=[f.result(timeout=22) for f in fs]
            if not ready:raise Skip('both workers did not reach synchronized consumption boundary')
        need(sum(outcomes)==1,'recovery code accepted by multiple OS processes or by neither')
        need(not one(codes[1],4),'raced credential accepted again')
        return dict(processes=2,synchronized=True,successful_consumptions=sum(outcomes))
    finally:
        for p in ps:
            if p.poll() is None:p.kill();p.communicate()

def recovery_worker():
    index=int(sys.argv[4]);code=sys.stdin.read();actor=os.environ['QV6_ACTOR']
    try:
        m=module('quantumvault.iam.recovery');path=find_database()
        with contextlib.closing(db_connection(path)) as conn:
            mgr=invoke(m.RecoveryManager,db_values(path,conn));fn=getattr(mgr,'verify_and_consume',None)
            if not callable(fn):raise Skip('verify_and_consume unavailable')
            vals={n:actor for n in ('actor','actor_id','identity','identity_id','user_id','account_id','username')};vals.update(code=code,recovery_code=code,credential=code)
            (state/('ready-'+str(index))).touch();end=time.monotonic()+12
            while not (state/('gate-'+str(index))).exists():
                if time.monotonic()>end:raise Skip('worker gate timed out')
                time.sleep(.005)
            try:r=invoke(fn,vals)
            except Exception as e:
                if isinstance(e,Skip):raise
                if type(e).__name__ in ('SecurityPolicyError','AuthenticationError','AuthorizationError','RecoveryError','CryptoError','ValueError','StateError'):r=False
                else:raise
            if isinstance(r,dict):r=pick(r,'success','valid','accepted')
            if type(r) is not bool:raise Skip('nonboolean recovery result')
            out={'accepted':r}
    except Skip as e:out={'skip':str(e)}
    except Exception as e:out={'error':type(e).__name__}
    print('QV6_WORKER '+json.dumps(out))

if kind=='recovery-worker':
    recovery_worker();sys.exit(0)

try:
    if kind=='window-oracle':result=window_oracle()
    elif kind=='audit-delete':result=audit_delete()
    elif kind=='backup-mutations':result=backup_probe()
    elif kind=='recovery-process-race':result=recovery_processes()
    else:raise Skip('unknown probe')
    output={'status':'PASS','observation':result}
except Skip as e:output={'status':'SKIP','detail':str(e)}
except Finding as e:output={'status':'FAIL','detail':str(e)}
except Exception as e:output={'status':'ERROR','detail':type(e).__name__+' (inspect local interface; details omitted)'}
print('QV6_RESULT '+json.dumps(output))
'''

# A distinct detection mutation built on V5's actual per-event prediction extraction.
DET = old.PROBE5.replace("    elif kind=='detection-duplicate':",r'''    elif kind=='detection-approval-substitution':
        # Keep all events unchanged except the approval identifier of a formerly approved role change.
        rs=copy.deepcopy(rows)
        target=next((r for r in rs if r.get('action')=='role_change' and baseline.get(r['event_id'])=='approved_change' and r.get('approval_id')),None)
        if target is None:raise Skip('approved role change / approval_id not found')
        target['approval_id']='nonexistent-'+secrets.token_hex(12)
        out=evaluate(state/'approval_substitution',rs,labels,approvals)
        need(out.get(target['event_id'])=='unexpected_role_change','role change with nonexistent approval not classified as unexpected')
    elif kind=='detection-duplicate':''')

class V6(old.V5):
    def __init__(self,*a,seed_value,**kw):
        super().__init__(*a,**kw);self.seed_value=seed_value
    def run_probe(self,kind,script=PROBE):
        s=self.state();env=self.env(s);env['QV6_SEED']=str(self.seed_value)
        if kind in ('audit-delete','backup-mutations','recovery-process-race'):
            self.setup(s)
        if kind=='recovery-process-race':env['QV6_ACTOR']=self.a
        if kind=='audit-delete':
            ids=['qv6-audit-'+secrets.token_hex(8) for _ in range(5)]
            for rid in ids:self.allow(self.req(s,self.a,self.x,rid),self.body)
            env['QV6_AUDIT_MIDDLE']=ids[2]
        probe_path=s/'qv6_probe.py';probe_path.write_text(script,encoding='utf-8')
        p=subprocess.run([sys.executable,str(probe_path),str(self.root),str(s),kind],cwd=s,env=env,capture_output=True,timeout=90)
        prefix='QV5_RESULT ' if script==DET else 'QV6_RESULT '
        lines=[x[len(prefix):] for x in p.stdout.decode('utf-8',errors='replace').splitlines() if x.startswith(prefix)]
        if p.returncode or len(lines)!=1:raise old.Skip('internal subprocess interface unavailable or no structured result')
        r=json.loads(lines[0]);status=r.get('status')
        if status=='SKIP':raise old.Skip(r['detail'])
        if status=='FAIL':raise old.Finding(r['detail'])
        if status!='PASS':raise RuntimeError(r.get('detail','internal error'))
        self.observations.append(dict(test=kind,**r.get('observation',{})))
    def read_revoke_cohort(self):
        s=self.state();actors=['actor-'+secrets.token_hex(6) for _ in range(8)];assets=['asset-'+secrets.token_hex(6) for _ in actors];bodies={a:'body-'+secrets.token_hex(24) for a in assets}
        self.setup_map(s,dict(zip(assets,actors)),bodies)
        for a,x in zip(actors,assets):self.allow(self.req(s,a,x),bodies[x])
        barrier=threading.Barrier(4)
        def revoke(a):barrier.wait(timeout=8);self.call(s,'revoke',actor=a)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(revoke,actors[:4]))
        for i,(a,x) in enumerate(zip(actors,assets)):
            rid=secrets.token_hex(12);r=self.req(s,a,x,rid)
            if i<4:self.deny(r);self.audit(s,rid,'deny')
            else:self.allow(r,bodies[x]);self.audit(s,rid,'allow')
        self.check_db(s)
    def audit_interleaving(self):
        s=self.state();self.setup(s);history=[]
        for i in range(4):
            for actor,asset,body,allowed in ((self.a,self.x,self.body,i<2),(self.b,self.y,self.peer,True),(self.a,self.y,None,False)):
                rid=secrets.token_hex(12);r=self.req(s,actor,asset,rid)
                if allowed:self.allow(r,body)
                else:self.deny(r)
                history.append((rid,'allow' if allowed else 'deny'))
            if i==1:self.call(s,'revoke',actor=self.a)
            self.rng.shuffle(history)
            for rid,d in history[::2]:self.audit(s,rid,d)
        for rid,d in history:self.audit(s,rid,d)
    def unicode_size(self):
        s=self.state();body=('ಕ🔐\r\né\x00'*1200)+self.body
        request=dict(op='setup',owners={self.x:self.a},contents={self.x:body},disabled=[],key_material=self.marker)
        payload=json.dumps(request,ensure_ascii=False).encode();old.require(len(payload)<65536,'fixture exceeds contract')
        self.setup_map(s,{self.x:self.a},{self.x:body});self.allow(self.req(s,self.a,self.x),body);self.deny(self.req(s,self.b,self.x))
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
    def pqc_mixed(self):
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise old.Skip('pqcrypto unavailable') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode();seen=set()
        for i in range(8):
            if i==4:self.call(s,'revoke',actor=self.a)
            a,x,body=(self.a,self.x,self.body) if i%2==0 else (self.b,self.y,self.peer)
            ch='qv6-'+str(i)+'-ಕ🔐';r=self.call(s,'protected_read',actor=a,asset=x,challenge=ch,public_key=pub)
            if i>=4 and a==self.a:self.deny(r);continue
            old.require(set(r)=={'ciphertext','proof'},'unexpected protected response fields');ct=base64.b64decode(r['ciphertext'],validate=True)
            old.require(len(ct)==1088 and ct not in seen,'invalid or repeated encapsulation ciphertext');seen.add(ct)
            ss=kem.decrypt(sk,ct);old.require(hmac.compare_digest(r['proof'],hmac.new(ss,(ch+body).encode(),hashlib.sha256).hexdigest()),'independent HMAC failed')
        self.observations.append(dict(test='pqc-mixed',verified=len(seen)))
    def restore_db_after_two_revokes(self):
        # Threat-model test: replace only quiescent DB image, keep live anchors intact.
        s=self.state();self.setup(s);dbs=self.databases(s)
        if len(dbs)!=1:raise old.Skip('requires one SQLite state database')
        db=dbs[0];snap=self.state()/'snapshot.sqlite'
        with contextlib.closing(sqlite3.connect(db)) as src,contextlib.closing(sqlite3.connect(snap)) as dst:src.backup(dst)
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
        self.call(s,'revoke',actor=self.b);self.deny(self.req(s,self.b,self.y))
        if not any(p.name in ('.cluster_epoch_anchor','external_checkpoints.json') for p in self.files(s)):raise old.Skip('external anchor unavailable')
        for suf in ('-wal','-shm','-journal'):Path(str(db)+suf).unlink(missing_ok=True)
        shutil.copyfile(snap,db)
        self.reject_raw(s,'read',actor=self.a,asset=self.x,request_id=secrets.token_hex(8));self.reject_raw(s,'read',actor=self.b,asset=self.y,request_id=secrets.token_hex(8))
    def persistent_audit_after_crash(self):
        s=self.state();self.setup(s);rid=secrets.token_hex(12);self.allow(self.req(s,self.a,self.x,rid),self.body);self.audit(s,rid,'allow')
        self.commit_kill(s,dict(op='revoke',actor=self.a),'after',r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE)\s+["`\[]?(?:revocations|identities)\b')
        new=secrets.token_hex(12);self.deny(self.req(s,self.a,self.x,new));self.audit(s,rid,'allow');self.audit(s,new,'deny');self.allow(self.req(s,self.b,self.y),self.peer);self.check_db(s)
    def malformed_after_commit(self):
        s=self.state();self.setup(s);self.call(s,'revoke',actor=self.a);rid=secrets.token_hex(12);self.deny(self.req(s,self.a,self.x,rid))
        for payload in (b'{"op":"setup","owners":{},"contents":{},"disabled":[],"key_material":null}',b'{"op":"revoke","actor":"x"}{}',b'{"op":"read","actor":"x","asset":"y","request_id":"r"}\xff'):
            self.no_disclosure(self.raw(s,payload));self.audit(s,rid,'deny');self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path);p.add_argument('--seed',type=int,default=60271);p.add_argument('--report',type=Path,default=Path('v6-results.json'));p.add_argument('--only');p.add_argument('--extended',action='store_true');p.add_argument('--self-test',action='store_true');p.add_argument('--list',action='store_true');a=p.parse_args()
    if a.self_test:
        old.self_test();compile(PROBE,'<v6-probe>','exec');compile(DET,'<v6-det>','exec');print('V6 probe syntax and inherited history-checker self-test passed');return 0
    definitions=[('cohort-revocation','contract','read_revoke_cohort'),('audit-interleaving','contract','audit_interleaving'),('large-unicode','contract','unicode_size'),('pqc-mixed','contract','pqc_mixed'),('two-revocation-db-rollback','threat-model','restore_db_after_two_revokes'),('postcommit-audit-history','resilience','persistent_audit_after_crash'),('malformed-after-commit','hardening','malformed_after_commit'),('window-oracle','adaptive','probe'),('audit-delete','adaptive','probe'),('backup-mutations','adaptive','probe'),('recovery-process-race','adaptive','probe'),('detection-approval-substitution','adaptive','detection')]
    if a.extended:definitions.extend([('linearizable-revocation','regression','test_linear_revoke'),('linearizable-generation','regression','test_linear_generations'),('cross-owner-ciphertext','regression','cross_owner_swap'),('web-origin','regression','oldprobe'),('web-session','regression','oldprobe'),('recovery-race','regression','oldprobe')])
    if a.list:
        for n,k,_ in definitions:print(n,k)
        return 0
    if a.repo is None or not (a.repo.resolve()/'track4_service.py').is_file():p.error('--repo must point to your own QuantumVault repository containing track4_service.py')
    root=a.repo.resolve();report=a.report.resolve()
    if report.exists():p.error('report already exists; choose a new filename')
    with tempfile.TemporaryDirectory(prefix='qv-v6-') as t:
        scratch=Path(t);copy=scratch/'source';old.copy_source5(root,copy);c=V6(copy,scratch,a.seed,seed_value=a.seed,rounds=4)
        selected=[d for d in definitions if not a.only or a.only.casefold() in d[0].casefold()]
        if not selected:p.error('no test matching --only')
        for n,k,m in selected:
            if m=='probe':fn=lambda n=n:c.run_probe(n)
            elif m=='detection':fn=lambda n=n:c.run_probe(n,DET)
            elif m=='oldprobe':fn=lambda n=n:c.probe(n)
            else:fn=getattr(c,m)
            c.run(n,k,fn)
        counts={k:sum(r['status']==k for r in c.results) for k in ('PASS','FAIL','ERROR','SKIP')}
        data=dict(version=6,seed=a.seed,adapter_calls=c.calls,counts=counts,results=c.results,observations=c.observations,limitations=['No exact project source was supplied to the author. Adaptive probes can skip on unsupported interfaces.','Direct DB rollback requires that external anchors are trusted; interpret against threat model.','No real services or production credentials; copied source is not an OS sandbox for untrusted code.','No independent direct IPC wire or E2EE handshake test without source interfaces.','Only window scheduling is deterministic from seed; cryptographic values and OS scheduling vary.'])
        with report.open('x',encoding='utf-8') as f:json.dump(data,f,indent=2)
        print('SUMMARY',counts,'adapter calls:',c.calls,'report:',report)
        return 1 if counts['FAIL'] or counts['ERROR'] else 2 if counts['SKIP'] else 0
if __name__=='__main__':sys.exit(main())
