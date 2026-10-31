"""Run panel tests against an owned, disposable synthetic lab. No live credentials required."""
from pathlib import Path
import json,os,secrets,shutil,socket,subprocess,tempfile,time,urllib.request

ROOT=Path(__file__).resolve().parents[2]

def main():
    go=shutil.which('go')
    portable=ROOT/'.tools/go/bin/go.exe'
    if not go and portable.exists():go=str(portable)
    node=shutil.which('node')
    if not go or not node:raise RuntimeError('Go and Node.js are required')
    if not (ROOT/'web/dist/index.html').exists():raise RuntimeError('Run npm --prefix web run build first')
    parent=(ROOT/'.local/e2e-runs').resolve();parent.mkdir(parents=True,exist_ok=True)
    temporary=tempfile.TemporaryDirectory(prefix='run-',dir=parent)
    directory=Path(temporary.name).resolve()
    assert directory.is_relative_to(parent) and directory.parent==parent
    process=None;log=None
    try:
        executable=directory/('wirewall.exe' if os.name=='nt' else 'wirewall')
        subprocess.run([go,'build','-o',str(executable),'./cmd/wirewall'],cwd=ROOT,check=True)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        base=f'http://127.0.0.1:{port}'
        env={**os.environ,'WIREWALL_TOKEN':secrets.token_hex(32),'WIREWALL_BASE_URL':base}
        log=(directory/'lab.log').open('wb')
        process=subprocess.Popen([str(executable),'serve','--backend','lab','--listen',f'127.0.0.1:{port}','--data',str(directory/'state'),'--policy',str(ROOT/'deploy/policy.lab.json'),'--web',str(ROOT/'web/dist')],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        for _ in range(60):
            if process.poll() is not None:raise RuntimeError('Disposable laboratory exited before readiness')
            try:
                with urllib.request.urlopen(base+'/api/v1/health',timeout=1) as r:
                    if json.load(r).get('backend')=='lab':break
            except OSError:pass
            time.sleep(0.2)
        else:raise RuntimeError('Disposable laboratory readiness timed out')
        result=subprocess.run([node,str(ROOT/'web/node_modules/@playwright/test/cli.js'),'test'],cwd=ROOT/'web',env=env)
        return result.returncode
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=6)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=6)
        if log:log.close()
        assert directory.is_relative_to(parent) and directory.parent==parent
        temporary.cleanup()

if __name__=='__main__':
    try:raise SystemExit(main())
    except (RuntimeError,subprocess.CalledProcessError) as exc:
        print(str(exc));raise SystemExit(1)
