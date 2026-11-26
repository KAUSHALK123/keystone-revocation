#!/usr/bin/env python3
"""Three distinct local test profiles for the documented QuantumVault adapter.
Uses V5/V6 utilities for selected regression and adaptive internal probes.
Never target remote systems. Only run trusted user-owned source.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import tempfile
import time
import sys
import v5_engine as base
import v6_engine as v6

need = base.require
Skip = base.Skip

class ThreeLevels(v6.V6):
    def basic_access(self):
        s = self.state(); self.setup(s, empty=True)
        self.allow(self.req(s, self.a, self.x), self.body)
        self.allow(self.req(s, self.b, self.y), '')
        for a,x in [(self.b,self.x),(self.c,self.z),(self.a,'missing'),('unknown',self.x)]:
            self.deny(self.req(s,a,x))

    def basic_revocation(self):
        s=self.state(); self.setup(s)
        rid=secrets.token_hex(12); self.allow(self.req(s,self.a,self.x,rid),self.body)
        self.call(s,'revoke',actor=self.a)
        denied=secrets.token_hex(12);self.deny(self.req(s,self.a,self.x,denied))
        self.audit(s,rid,'allow');self.audit(s,denied,'deny')
        self.allow(self.req(s,self.b,self.y),self.peer)

    def basic_reset(self):
        s=self.state(); self.setup(s);self.call(s,'revoke',actor=self.a)
        self.deny(self.req(s,self.a,self.x))
        self.setup_map(s,{self.x:self.b},{self.x:self.peer})
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.x),self.peer)
        self.deny(self.req(s,self.b,self.y))

    def basic_pqc(self):
        try: from pqcrypto.kem import ml_kem_768 as kem
        except ImportError: raise Skip('pqcrypto unavailable in current interpreter') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair()
        args=dict(actor=self.a,asset=self.x,challenge='challenge '+secrets.token_hex(16)+' ಕನ್ನಡ',public_key=base64.b64encode(pk).decode())
        r=self.call(s,'protected_read',**args)
        self.verify_proof(kem,sk,r,args['challenge'],self.body)
        self.deny(self.call(s,'protected_read',**dict(args,actor=self.b)))
        self.call(s,'revoke',actor=self.a);self.deny(self.call(s,'protected_read',**args))

    @staticmethod
    def verify_proof(kem,sk,r,ch,body):
        need(set(r)=={'ciphertext','proof'},'unexpected protected_read output fields')
        ct=base64.b64decode(r['ciphertext'],validate=True)
        need(len(ct)==1088,'invalid KEM ciphertext size')
        ss=kem.decrypt(sk,ct)
        need(hmac.compare_digest(r['proof'],hmac.new(ss,(ch+body).encode(),hashlib.sha256).hexdigest()),'independent KEM/HMAC proof mismatch')
        need(ss.hex() not in json.dumps(r) and base64.b64encode(ss).decode() not in json.dumps(r),'shared secret disclosed')
        return ct

    def multi_asset(self):
        # One owner holds multiple assets, and two independent peers remain unaffected.
        s=self.state(); extra='asset-'+secrets.token_hex(8); p='peer-'+secrets.token_hex(8)
        owners={self.x:self.a,extra:self.a,self.y:self.b,self.z:p}
        bodies={self.x:self.body,extra:'QV_EXTRA_'+secrets.token_hex(24),self.y:self.peer,self.z:self.disabled_body}
        self.setup_map(s,owners,bodies)
        for x,a in owners.items():self.allow(self.req(s,a,x),bodies[x])
        self.call(s,'revoke',actor=self.a)
        for x,a in owners.items():
            rid=secrets.token_hex(12); r=self.req(s,a,x,rid)
            if a==self.a:self.deny(r);self.audit(s,rid,'deny')
            else:self.allow(r,bodies[x]);self.audit(s,rid,'allow')
        self.deny(self.req(s,self.b,extra))

    def different_key_states(self):
        # Same opaque IDs but different content, key material, and disabled state.
        s,t=self.state(),self.state();self.setup(s)
        key='QV_SECOND_KEY_'+secrets.token_hex(32)
        self.setup_map(t,{self.x:self.a,self.y:self.b},{self.x:self.peer,self.y:self.body},[self.b],key=key)
        self.call(s,'revoke',actor=self.a)
        self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
        self.allow(self.req(t,self.a,self.x),self.peer);self.deny(self.req(t,self.b,self.y))
        self.call(t,'revoke',actor=self.a);self.deny(self.req(t,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)

    def fresh_generation_pqc(self):
        try: from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        s=self.state();self.setup(s);pk,sk=kem.generate_keypair();ch='fixed challenge '+secrets.token_hex(12)
        args=dict(actor=self.a,asset=self.x,challenge=ch,public_key=base64.b64encode(pk).decode())
        c1=self.verify_proof(kem,sk,self.call(s,'protected_read',**args),ch,self.body)
        self.call(s,'revoke',actor=self.a);self.deny(self.call(s,'protected_read',**args))
        self.setup_map(s,{self.x:self.a},{self.x:self.peer},key='generation-'+secrets.token_hex(32))
        c2=self.verify_proof(kem,sk,self.call(s,'protected_read',**args),ch,self.peer)
        need(c1!=c2,'encapsulation ciphertext repeated across generations')
        self.deny(self.req(s,self.b,self.x))

    def history_mixed_oracle(self):
        # New combined model: read, audit of committed request, protected_read and revoke
        # in a single bounded history, plus quiescent probes. All actual KEM results
        # independently verified before model checking. Setup is outside history.
        try:from pqcrypto.kem import ml_kem_768 as kem
        except ImportError:raise Skip('pqcrypto unavailable') from None
        for _ in range(self.rounds):
            s=self.state();self.setup(s)
            owners={self.x:self.a,self.y:self.b,self.z:self.c};bodies={self.x:self.body,self.y:self.peer,self.z:self.disabled_body}
            past=secrets.token_hex(12);self.allow(self.req(s,self.a,self.x,past),self.body)
            pk,sk=kem.generate_keypair();pub=base64.b64encode(pk).decode()
            def op(name,**args):return dict(op=name,args=args,delay=self.rng.uniform(0,.06))
            ops=[op('revoke',actor=self.a),op('audit',request_id=past),
                 op('read',actor=self.a,asset=self.x,request_id=secrets.token_hex(12)),
                 op('read',actor=self.b,asset=self.y,request_id=secrets.token_hex(12)),
                 op('read',actor=self.c,asset=self.z,request_id=secrets.token_hex(12)),
                 op('protected_read',actor=self.a,asset=self.x,challenge=secrets.token_hex(16),public_key=pub),
                 op('protected_read',actor=self.b,asset=self.y,challenge=secrets.token_hex(16),public_key=pub),
                 op('protected_read',actor=self.b,asset=self.x,challenge=secrets.token_hex(16),public_key=pub)]
            self.rng.shuffle(ops);history=self.history(s,ops)
            for item in history:
                if item['op']=='protected_read':
                    r=item['result'];a=item['args']
                    if r.get('decision')=='deny':self.deny(r)
                    else:self.verify_proof(kem,sk,r,a['challenge'],bodies[a['asset']])
            # Independent transition model, no project policy calls.
            def step(disabled,item):
                r=item['result'];args=item['args'];kind=item['op']
                if kind=='audit':return disabled if r=={'request_id':past,'decision':'allow'} else None
                if kind=='revoke':return disabled|frozenset([args['actor']])
                a,x=args['actor'],args['asset'];allowed=owners.get(x)==a and a not in disabled
                if kind=='read':expected={'decision':'allow','body':bodies[x]} if allowed else {'decision':'deny'}
                else:return disabled if allowed==('proof' in r) else None
                return disabled if r==expected else None
            w=base.linearizable(frozenset([self.c]),history,step)
            self.record_history('mixed-audit-read-kem-revoke',history,w)
            need(w is not None,'no legal sequential history explains mixed audit/read/KEM/revoke responses')
            for item in history:
                if item['op']=='read':self.audit(s,item['args']['request_id'],item['result']['decision'])
            self.deny(self.req(s,self.a,self.x));self.allow(self.req(s,self.b,self.y),self.peer)
            self.deny(self.call(s,'protected_read',actor=self.a,asset=self.x,challenge='after-revocation',public_key=pub))

    def rollback_isolation(self):
        # Extra threat-model check: rollback one state without changing a second.
        import sqlite3, contextlib, shutil
        s,t=self.state(),self.state();self.setup(s);self.setup(t)
        dbs=self.databases(s)
        if len(dbs)!=1:raise Skip('requires one SQLite database in isolated state')
        db=dbs[0];snapshot=self.state()/'snapshot.sqlite'
        with contextlib.closing(sqlite3.connect(db)) as src,contextlib.closing(sqlite3.connect(snapshot)) as dst:src.backup(dst)
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
        self.allow(self.req(t,self.a,self.x),self.body)
        if not any(p.name in ('.cluster_epoch_anchor','external_checkpoints.json') for p in self.files(s)):raise Skip('no recognized external security anchor')
        # No open target processes/connections at this point.
        for ext in ('-wal','-shm','-journal'):Path(str(db)+ext).unlink(missing_ok=True)
        shutil.copyfile(snapshot,db)
        self.reject_raw(s,'read',actor=self.a,asset=self.x,request_id=secrets.token_hex(12))
        self.allow(self.req(t,self.a,self.x),self.body);self.allow(self.req(t,self.b,self.y),self.peer)

    def audit_crash_cycle(self):
        # Combine the two actual commit-boundary probes in one state, with a surviving peer.
        s=self.state();self.setup_map(s,{self.x:self.a,self.y:self.b,self.z:self.c},{self.x:self.body,self.y:self.peer,self.z:self.disabled_body})
        rid=secrets.token_hex(12);self.allow(self.req(s,self.a,self.x,rid),self.body)
        pattern=r'^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE)\s+["`\[]?(?:revocations|identities)\b'
        self.commit_kill(s,dict(op='revoke',actor=self.a),'before',pattern)
        r=self.req(s,self.a,self.x)
        if r.get('decision')=='allow':self.allow(r,self.body)
        else:self.deny(r)  # conservative fail-closed recovery is permitted for interrupted revoke
        self.audit(s,rid,'allow');self.allow(self.req(s,self.b,self.y),self.peer)
        self.call(s,'revoke',actor=self.a);self.deny(self.req(s,self.a,self.x))
        self.commit_kill(s,dict(op='revoke',actor=self.b),'after',pattern)
        denied=secrets.token_hex(12);self.deny(self.req(s,self.b,self.y,denied));self.deny(self.req(s,self.a,self.x))
        self.audit(s,rid,'allow');self.audit(s,denied,'deny');self.allow(self.req(s,self.c,self.z),self.disabled_body)
        self.check_db(s)

# Independent profiles: deliberately not cumulative. Reused V5/V6 probes are named.
PROFILES={
'easy':[
('basic-access','contract','basic_access'),('basic-revoke-audit','contract','basic_revocation'),
('basic-reset','contract','basic_reset'),('basic-pqc','contract','basic_pqc'),('opaque-identifiers','contract','opaque')],
'normal':[
('multiple-assets-per-owner','contract','multi_asset'),('different-key-state-isolation','contract','different_key_states'),
('new-generation-pqc-binding','contract','fresh_generation_pqc'),('malformed-key-handling','hardening','bad_keys'),
('malformed-reset-atomicity','hardening','test_malformed_state'),('plaintext-at-rest','storage','disk_plaintext'),
('nonce-uniqueness','storage','nonce_uniqueness'),('audit-interleaving','contract','audit_interleaving'),
('detector-label-independence','adaptive','detection-labels'),('web-origin','adaptive','web-origin')],
'extreme':[
('mixed-history-oracle','hardening','history_mixed_oracle'),('competing-setup-generations','hardening','test_linear_generations'),
('crash-before-and-after-commit','resilience','audit_crash_cycle'),('rollback-with-isolated-peer','threat-model','rollback_isolation'),
('cross-owner-ciphertext-swap','threat-model','cross_owner_swap'),('same-owner-ciphertext-swap','threat-model','same_owner_swap'),
('noncanonical-kem-coefficients','crypto-hardening','test_partial_kem_coefficients'),('four-way-cohort-revocation','hardening','read_revoke_cohort'),
('replay-window-501-operations','adaptive','window-oracle'),('recovery-two-process-race','adaptive','recovery-process-race'),
('backup-authentication-mutations','adaptive','backup-mutations'),('audit-event-deletion','adaptive','audit-delete'),
('detector-approval-substitution','adaptive','detection-approval-substitution'),('detector-renamed-identifiers','adaptive','detection-ids'),
('detector-shifted-clock','adaptive','detection-time'),('web-session-lifecycle','adaptive','web-session')]
}

V6_PROBES={'window-oracle','recovery-process-race','backup-mutations','audit-delete'}
V5_PROBES={'detection-labels','detection-ids','detection-time','web-origin','web-session'}

def run(profile):
    ap=argparse.ArgumentParser(description=f'QuantumVault {profile.upper()} local test profile')
    ap.add_argument('--repo',type=Path);ap.add_argument('--seed',type=int,default=73026)
    ap.add_argument('--rounds',type=int,choices=range(1,9),default=3,help='extreme concurrent history repetitions')
    ap.add_argument('--report',type=Path);ap.add_argument('--only');ap.add_argument('--list',action='store_true');ap.add_argument('--self-test',action='store_true')
    a=ap.parse_args();definitions=PROFILES[profile]
    if a.list:
        for n,k,_ in definitions:print(n,k)
        return 0
    if a.self_test:
        base.self_test();compile(v6.PROBE,'<v6-probe>','exec');compile(v6.DET,'<v6-det>','exec')
        for n,k,m in definitions:
            if m not in V6_PROBES|V5_PROBES|{'detection-approval-substitution'}:need(callable(getattr(ThreeLevels,m,None)),f'missing test: {n}')
        print(f'{profile}: registry and inherited oracle self-tests passed (not a project test)');return 0
    if a.repo is None or not (a.repo.resolve()/'track4_service.py').is_file():ap.error('--repo must point to your own repository root containing track4_service.py')
    report=(a.report or Path(f'{profile}-results.json')).resolve()
    report.unlink(missing_ok=True)
    selected=[d for d in definitions if not a.only or a.only.casefold() in d[0].casefold()]
    if not selected:ap.error('no matching test names')
    with tempfile.TemporaryDirectory(prefix='qv-three-level-', ignore_cleanup_errors=True) as tmp:
        scratch=Path(tmp);source=scratch/'source';base.copy_source5(a.repo.resolve(),source)
        c=ThreeLevels(source,scratch,a.seed,seed_value=a.seed,rounds=a.rounds)
        for n,k,m in selected:
            if m in V6_PROBES:fn=lambda m=m:c.run_probe(m)
            elif m in V5_PROBES:fn=lambda m=m:c.probe(m)
            elif m=='detection-approval-substitution':fn=lambda:c.run_probe(m,v6.DET)
            else:fn=getattr(c,m)
            c.run(n,k,fn)
        counts={k:sum(r['status']==k for r in c.results) for k in ('PASS','FAIL','ERROR','SKIP')}
        payload=dict(profile=profile,seed=a.seed,rounds=a.rounds,adapter_calls=c.calls,counts=counts,results=c.results,observations=c.observations,
            limitations=['Source copied into temporary directory; not a hardened OS sandbox. Never run untrusted code.','Uses V5/V6 regression helpers plus new profile-specific tests. Not official or hidden judge tests.','Adaptive probes may skip when signatures, dependencies or fixtures unavailable; SKIP is not PASS.','Direct database mutation and malformed input requirements may exceed official contract; interpret in threat model.','Seed controls scheduling choices; cryptographic data and actual scheduling vary.','No complete direct IPC, outbox or E2EE protocol audit without source interfaces.'])
        with report.open('x',encoding='utf-8') as f:json.dump(payload,f,indent=2)
        print('SUMMARY',counts,'adapter calls:',c.calls,'report:',report)
        return 1 if counts['FAIL'] or counts['ERROR'] else 2 if counts['SKIP'] else 0
