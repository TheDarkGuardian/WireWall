#!/usr/bin/env python3
"""Bounded sustained native-XDP stability test; disposable private netns only."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--rounds',type=int,default=10)
    args=parser.parse_args()
    if os.geteuid()!=0 or os.environ.get('WIREWALL_ALLOW_NETNS_BENCHMARK')!='1':raise SystemExit('Root and explicit netns benchmark opt-in required')
    if not 1<=args.rounds<=20:raise SystemExit('Rounds must be 1..20, 30 seconds each')
    args.output=args.output.resolve();args.output.mkdir(parents=True,exist_ok=False,mode=0o700)
    client=f'ww-soak-c-{os.getpid()}';server=f'ww-soak-s-{os.getpid()}'
    client_link=f'wwsc-{os.getpid()}';server_link=f'wwss-{os.getpid()}'
    created=[];processes=[];linked=False;stack=ExitStack()
    env=os.environ.copy();env['WIREWALL_BENCH_PAYLOAD_BYTES']='512'
    def run(command,**kwargs):return subprocess.run(command,check=True,env=env,**kwargs)
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=12)
            except subprocess.TimeoutExpired:process.kill();process.wait()
    def launch(namespace,command,log):
        stream=log.open('w');process=subprocess.Popen(['ip','netns','exec',namespace]+command,stdout=stream,stderr=subprocess.STDOUT,env=env);stream.close();processes.append(process);stack.callback(stop,process);return process
    try:
        for namespace in [client,server]:run(['ip','netns','add',namespace]);created.append(namespace)
        run(['ip','link','add',client_link,'type','veth','peer','name',server_link]);linked=True
        run(['ip','link','set',client_link,'netns',client]);run(['ip','link','set',server_link,'netns',server])
        for namespace,link,name,address in [(client,client_link,'ww-client','10.203.0.1/24'),(server,server_link,'ww-server','10.203.0.2/24')]:
            run(['ip','-n',namespace,'link','set',link,'name',name]);run(['ip','-n',namespace,'link','set','lo','up']);run(['ip','-n',namespace,'addr','add',address,'dev',name]);run(['ip','-n',namespace,'link','set',name,'up'])
        with stack:
            directory=stack.enter_context(tempfile.TemporaryDirectory(prefix='wirewall-soak-'))
            temporary=Path(directory)
            policy={'version':1,'mode':'enforce','interface':'ww-server','xdpMode':'native','managementCidrs':['10.203.0.1/32'],'managementPort':22,'host':{'tcpPorts':[],'udpPorts':[9000],'ipv6':False},'rules':[]}
            for i in range(63):policy['rules'].append({'id':f'padding-{i}','name':f'nonmatch {i}','enabled':True,'priority':i,'action':'drop','protocol':'udp','source':'10.203.0.254/32','destination':'any','sourcePort':'any','destinationPort':'any','minPacketBytes':0,'maxPacketBytes':0,'pps':0,'burst':0})
            policy['rules'].append({'id':'deny-background','name':'background','enabled':True,'priority':100,'action':'drop','protocol':'udp','source':'any','destination':'any','sourcePort':'any','destinationPort':'9001','minPacketBytes':0,'maxPacketBytes':0,'pps':0,'burst':0})
            path=temporary/'policy.json';path.write_text(json.dumps(policy))
            helper=str(ROOT/'scripts/linux/bench_traffic.py')
            echo=launch(server,['python3',helper,'server','--ready',str(temporary/'echo-ready.json')],args.output/'echo.log')
            for _ in range(60):
                if echo.poll() is not None:raise RuntimeError('Echo server exited')
                if (temporary/'echo-ready.json').exists():break
                time.sleep(.1)
            else:raise RuntimeError('Echo readiness timeout')
            firewall=launch(server,[str(ROOT/'bin/wirewall'),'serve','--backend','xdp','--confirm-network-changes','--policy',str(path),'--object',str(ROOT/'bpf/wirewall_bpfel.o'),'--data',str(temporary/'state'),'--listen','127.0.0.1:9876'],args.output/'firewall.log')
            def api(path,output):run(['ip','netns','exec',server,'python3',helper,'api','--path',path,'--token-file',str(temporary/'state/operator.token'),'--output',str(output)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(80):
                if firewall.poll() is not None:raise RuntimeError('Native XDP startup failed; no fallback used')
                try:api('health',temporary/'health.json');break
                except subprocess.CalledProcessError:time.sleep(.15)
            else:raise RuntimeError('Firewall readiness timeout')
            api('policy/confirm',temporary/'confirmed.json')
            run(['ip','-n',server,'-j','link','show','ww-server'],stdout=(args.output/'active-interface.json').open('w'))
            started=time.monotonic();results=[]
            for index in range(args.rounds):
                result_path=args.output/f'round-{index+1:02}.json'
                run(['ip','netns','exec',client,'python3',helper,'client','--duration','30','--legitimate-rate','500','--background-rate','5000','--output',str(result_path)])
                data=json.loads(result_path.read_text());assert data['streams']['legitimate']['successRatio']==1 and data['streams']['background']['successRatio']==0
                snapshot_path=args.output/f'snapshot-{index+1:02}.json';api('snapshot',snapshot_path);snapshot=json.loads(snapshot_path.read_text())
                assert snapshot['system']['attached'] and snapshot['system']['xdpMode']=='native' and not snapshot['system']['activationPending']
                results.append({'round':index+1,'received':snapshot['metrics']['receivedPackets'],'dropped':snapshot['metrics']['droppedPackets'],'eventDrops':snapshot['metrics']['eventDrops']})
                (args.output/'progress.json').write_text(json.dumps(results,indent=2));print('PASS sustained round',index+1,flush=True)
            summary={'passed':True,'rounds':args.rounds,'elapsedSeconds':time.monotonic()-started,'mode':'native','rules':64,'payloadBytes':512,'scope':'One persistent firewall instance in disposable namespaces; no host uplink traffic or exclusive CPU claim','results':results}
            (args.output/'summary.json').write_text(json.dumps(summary,indent=2))
            print('NATIVE_SOAK_PASS',flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=12)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        for namespace in reversed(created):
            for pid in subprocess.check_output(['ip','netns','pids',namespace],text=True).split():
                try:os.kill(int(pid),signal.SIGTERM)
                except ProcessLookupError:pass
            subprocess.run(['ip','netns','del',namespace],check=False)
        if linked:subprocess.run(['ip','link','del',client_link],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
