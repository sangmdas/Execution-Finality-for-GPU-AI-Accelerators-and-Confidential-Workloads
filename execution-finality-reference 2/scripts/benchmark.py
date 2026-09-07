from __future__ import annotations

import statistics
import sys
import time
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import cryptography

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from finality.profile import EATPolicy, appraise_eat, candidate_act, issue_handle, issue_test_eat, verify_handle


def measure(name, fn, samples=10000):
    for _ in range(1000): fn()
    values=[]
    for _ in range(samples):
        start=time.perf_counter_ns(); fn(); values.append((time.perf_counter_ns()-start)/1000)
    values.sort()
    pick=lambda p: values[min(len(values)-1, int(len(values)*p))]
    print(f"{name}: n={samples} median={statistics.median(values):.2f}us p95={pick(.95):.2f}us p99={pick(.99):.2f}us")


now=int(time.time()); eat_key=Ed25519PrivateKey.generate(); handle_key=Ed25519PrivateKey.generate()
measurement=bytes.fromhex("11"*32); body=b'{"destination":"account-B","amount":100,"currency":"USD"}'
eat=issue_test_eat(eat_key,b"eat-1","urn:bench:attester","agent-47",measurement,b"x"*24,now)
policy=EATPolicy("urn:bench:attester",measurement); eat_keys={b"eat-1":eat_key.public_key()}
workload,context=appraise_eat(eat,eat_keys,policy,"urn:bench:verifier",now)
act=candidate_act("POST","payments.example","/transfer",body,"urn:example:finality-sink:payments","tx-0123456789abcdef")
handle=issue_handle(handle_key,b"efv-1",act,workload,context,now=now,nonce=b"n"*24); handle_keys={b"efv-1":handle_key.public_key()}
print(f"platform={platform.platform()}")
print(f"machine={platform.machine()} processor={platform.processor() or 'not-reported'}")
print(f"python={platform.python_version()} cryptography={cryptography.__version__}")
print("algorithm=Ed25519 hash=SHA-256 replay_store=not-included body_bytes=58 warmup=1000 samples=10000 concurrency=1")
measure("cold-path EAT appraisal",lambda:appraise_eat(eat,eat_keys,policy,"urn:bench:verifier",now))
measure("CandidateAct construction",lambda:candidate_act("POST","payments.example","/transfer",body,"urn:example:finality-sink:payments","tx-0123456789abcdef"))
measure("handle issuance",lambda:issue_handle(handle_key,b"efv-1",act,workload,context,now=now))
measure("handle verification",lambda:verify_handle(handle,handle_keys,act,now))
