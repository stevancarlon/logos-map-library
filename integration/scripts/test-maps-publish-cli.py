#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Real terminal map registration/cancellation/recovery against a disposable v0.3 node."""
import argparse, hashlib, json, os, pty, re, select, signal, subprocess, tempfile, termios, time
from pathlib import Path
from urllib.parse import urlsplit
from fixture_process import install_termination_handler
install_termination_handler()
ROOT=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser()
parser.add_argument('--rpc',required=True)
parser.add_argument('--program',required=True)
parser.add_argument('--binary',type=Path,required=True)
parser.add_argument('--storage')
parser.add_argument('--source',type=Path)
parser.add_argument('--version')
args=parser.parse_args()
u=urlsplit(args.rpc)
if u.scheme!='http' or u.hostname!='127.0.0.1' or not u.port: parser.error('Loopback fixture only')
if args.storage and (not args.source or not args.version):parser.error('Authentic host fixture needs source and version')
binary=args.binary.resolve()
password=b'maps-terminal-fixture-password\n'
seed=b'01'*32+b'\n'
secret_values=[password,seed]

def terminal(arguments, responses, *, expected=0, review_terms=(), redirect=False):
    stdout_file = scratch/'stdout.json'
    pid, fd = pty.fork()
    if pid == 0:
        if redirect:
            out = os.open(stdout_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(out, 1)
            os.close(out)
        os.execv(str(binary), [str(binary), *map(str, arguments)])
    pending = list(responses)
    output = b''
    recent = b''
    reaped = False
    try:
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b''
                output += data
                recent += data
                if pending and pending[0][0] in recent:
                    prompt, answer = pending.pop(0)
                    if b'password' in prompt.lower() or b'hidden' in prompt:
                        assert not termios.tcgetattr(fd)[3] & termios.ECHO, 'Secret prompt visible before echo disabled'
                        cmdline = Path(f'/proc/{pid}/cmdline')
                        if cmdline.exists():
                            assert answer.strip() not in cmdline.read_bytes(), 'Secret appeared in argv'
                    if b'anything else cancels' in prompt:
                        for required in review_terms:
                            assert required in output, ('Missing review field', required)
                        if answer is None or answer==b'oversized':
                            oversized=answer==b'oversized'
                            digest=re.search(rb'Type APPROVE ([0-9a-f]{64}) to sign',recent).group(1)
                            answer=b'APPROVE '+digest+(b' '*300+b'NO\n' if oversized else b'\n')
                    os.write(fd, answer)
                    recent = b''
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                reaped = True
                # Drain bytes delivered just before exit before interpreting JSON.
                while select.select([fd], [], [], 0)[0]:
                    try:
                        data = os.read(fd, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
                assert os.waitstatus_to_exitcode(status) == expected, output.decode(errors='replace')
                assert not pending, ('Missing prompt', pending, output)
                if redirect:
                    output += stdout_file.read_bytes()
                for secret in secret_values:
                    assert secret.strip() not in output, 'Secret was echoed or printed'
                return output.decode()
        raise TimeoutError('CLI fixture command timed out')
    finally:
        os.close(fd)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if not reaped:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def result(text):
    for line in reversed(text.splitlines()):
        if line.startswith(('{', '[')):
            try:
                return json.loads(line)
            except ValueError:
                pass
    raise AssertionError('Missing JSON result: '+text)



with tempfile.TemporaryDirectory(prefix='maps-publisher-cli-') as temporary:
    scratch=Path(temporary)
    key=scratch/'key.vault';outbox=scratch/'outbox.sqlite';snapshots=scratch/'snapshots.json'
    imported=result(terminal(['key-import',key],[(b'hidden): ',seed),(b'New password: ',password),(b'Repeat password: ',password)]))
    assert key.stat().st_mode&0o777==0o600
    terminal(['outbox-create',outbox],[(b'New password: ',password),(b'Repeat password: ',password)])
    snapshot={'region':'africa/kenya','parent':None,'level':'country','cid':'bafySyntheticTerminalFixture','source_url':'https://download.geofabrik.de/africa/kenya-latest.osm.pbf','checksum':[1]*16,'sha256':[2]*32,'bytes':3,'version':20261009,'hosted':True}
    snapshots.write_text(json.dumps([snapshot]))
    command=['register',args.rpc,args.program,key,outbox,snapshots,'10000000','500000000','0']
    prompts=[(b'Key vault password: ',password),(b'Outbox password: ',password)]
    review_terms=[b'MAP REGISTRATION REVIEW',args.program.encode(),imported['account'].encode(),b'"nonce"',b'"quoted_reserve"',b'"payer_balance"',b'"quote_height"',b'"max_fee": "500000000"',b'africa/kenya',b'bafySyntheticTerminalFixture']
    too_low=command.copy();too_low[-2]='1'
    rejected_fee=terminal(too_low,prompts,expected=1)
    assert 'fee quote exceeds approved cap' in rejected_fee
    unaffordable=command.copy();unaffordable[-2]='100000000000000000000'
    rejected_balance=terminal(unaffordable,prompts,expected=1)
    assert 'insufficient balance for approved maximum fee' in rejected_balance
    canceled=result(terminal(command,prompts+[(b'anything else cancels: ',b'no\n')],review_terms=review_terms))
    assert canceled=={'status':'canceled','submitted':False}
    overflow=result(terminal(command,prompts+[(b'anything else cancels: ',b'oversized')],review_terms=review_terms))
    assert overflow=={'status':'canceled','submitted':False}
    history=result(terminal(['history',outbox],[(b'Outbox password: ',password)]));assert history==[]
    next_command=command.copy();next_command[0]='register-next'
    submitted=result(terminal(next_command,prompts+[(b'anything else cancels: ',None)],review_terms=review_terms))
    assert submitted['status'] in ['acknowledged','submission_unknown']
    for _ in range(10):
        recovered=result(terminal(['reconcile',args.rpc,outbox,submitted['hash']],[(b'Outbox password: ',password)]))
        if recovered['status']=='observed':break
        time.sleep(.5)
    else:raise AssertionError('Saved CLI submission not observed')
    history=result(terminal(['history',outbox],[(b'Outbox password: ',password)]))
    assert len(history)==1 and history[0]['hash']==submitted['hash'] and history[0]['status']=='observed'
    records=json.loads(subprocess.check_output([ROOT/'target/debug/maps-v03','registry-page',args.rpc,args.program,'0','region','africa/kenya'],text=True))
    assert any(r['snapshot']==snapshot for r in records['records'])
    completion_text=terminal(next_command,prompts)
    assert result(completion_text)=={'complete':True,'verification':'matching_registry_records_by_author'}
    assert 'Type APPROVE' not in completion_text
    assert len(result(terminal(['history',outbox],[(b'Outbox password: ',password)])))==1
    rejected=subprocess.run([binary,*map(str,command)],input='',text=True,capture_output=True)
    assert rejected.returncode!=0 and 'Interactive terminal required' in rejected.stderr
    assert b'REGKEY01' not in key.read_bytes() and imported['account'].encode() not in outbox.read_bytes()
    host_evidence=None
    if args.storage:
        receipt=scratch/'host-receipt.json'
        host=['host-local',args.rpc,args.program,args.storage,'africa/ethiopia',args.version,
              args.source,'150000000',receipt,key,outbox,'10000000','500000000','0']
        canceled_host=result(terminal(host,prompts+[(b'anything else cancels: ',b'no\n')],
            review_terms=[b'africa/ethiopia',b'MAP REGISTRATION REVIEW']))
        assert canceled_host['status']=='canceled' and canceled_host['complete'] is False
        stored=json.loads(receipt.read_text());assert len(stored)==1 and stored[0]['region']=='africa/ethiopia'
        assert stored[0]['bytes']==args.source.stat().st_size
        saved=receipt.read_bytes()
        terminal(host,prompts,expected=1)
        assert receipt.read_bytes()==saved,'Existing receipt overwritten'
        assert len(result(terminal(['history',outbox],[(b'Outbox password: ',password)])))==1
        resume=['publish-all',args.rpc,args.program,key,outbox,receipt,'10000000','500000000','0']
        published=result(terminal(resume,prompts+[(b'anything else cancels: ',None)],
            review_terms=[b'africa/ethiopia',stored[0]['cid'].encode()]))
        assert published['complete'] and len(published['transactions'])==1
        again=result(terminal(resume,prompts))
        assert again['complete'] and again['transactions']==[]
        destination=scratch/'downloaded.pbf'
        subprocess.run([ROOT/'target/debug/maps-v03','download-snapshot',args.storage,json.dumps(stored[0]),
                        '150000000',destination],check=True,stdout=subprocess.DEVNULL)
        def sha(path):
            with path.open('rb') as file:return hashlib.file_digest(file,'sha256').digest()
        assert sha(destination)==sha(args.source)==bytes(stored[0]['sha256'])
        items=scratch/'items.json'
        items.write_text(json.dumps([
            {'region':'africa/ethiopia','version':int(args.version),'selected':True,'input':{'kind':'local','path':str(args.source)}},
            {'region':'africa/kenya','version':int(args.version),'selected':True,'input':{'kind':'local','path':str(scratch/'missing.pbf')}},
            {'region':'africa/egypt','version':int(args.version),'selected':False,'input':{'kind':'local','path':str(scratch/'missing.pbf')}}
        ]))
        partial=result(terminal(['host-bulk',args.rpc,args.program,args.storage,items,'150000000',
                                 scratch/'bulk-receipt.json',key,outbox,'10000000','500000000','0'],prompts))
        assert partial['complete'] is False and partial['registration_complete'] is True
        assert partial['failed_regions']==1 and partial['status']=='partially_registered'
        assert len(partial['stored_snapshots'])==1 and len(partial['hosting_outcomes'])==2
        latest=json.loads(subprocess.check_output([ROOT/'target/debug/maps-v03','latest-version','africa/ethiopia'],text=True))['version']
        fetched_file=scratch/'fetched-latest.pbf';fetch_receipt=scratch/'fetch-receipt.json'
        fetch_command=['host-fetch',args.rpc,args.program,args.storage,'africa/ethiopia',str(latest),
            fetched_file,'150000000',fetch_receipt,key,outbox,'10000000','500000000','0']
        fetch_prompts=prompts+([(b'anything else cancels: ',None)] if latest!=int(args.version) else [])
        fetched=result(terminal(fetch_command,fetch_prompts,review_terms=[b'africa/ethiopia']))
        assert fetched['complete'] and fetched['registration_complete']
        fresh=json.loads(fetch_receipt.read_text());assert len(fresh)==1 and fresh[0]['version']==latest
        fetched_download=scratch/'fetched-retrieved.pbf'
        subprocess.run([ROOT/'target/debug/maps-v03','download-snapshot',args.storage,json.dumps(fresh[0]),
                        '150000000',fetched_download],check=True,stdout=subprocess.DEVNULL)
        assert sha(fetched_file)==sha(fetched_download)==bytes(fresh[0]['sha256'])
        host_evidence={'authentic_storage_roundtrip':True,'snapshot':stored[0],
            'fetch_store_register_roundtrip':True,'fetched_snapshot':fresh[0],
            'fetch_registration_submitted':len(fetched['transactions'])==1,
            'cancel_preserves_receipt':True,'existing_receipt_not_overwritten':True,'resume_without_upload':True,
            'no_duplicate_submission':True,'partial_bulk_and_opt_out':True,'registration_hash':published['transactions'][0]}
    print(json.dumps({'result':'passed','scope':'real PTY and disposable v0.3 sequencer; synthetic Kenya snapshot; fixed test key', 'combined_host':host_evidence,'hidden_secrets':True,'cancellation_without_submission':True,'nonterminal_rejected':True,'oversized_approval_rejected':True,'low_fee_cap_rejected':True,'unaffordable_cap_rejected':True,'signed_hash':submitted['hash'],'reopened_outbox_observed':True,'planned_registration':True,'registry_completion_without_new_approval':True,'resulting_record_checked':True,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
