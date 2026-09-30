"""S3-shaped adapter for the locally authenticated Wrangler remote R2 binding."""
import base64
import io
import json
import subprocess
import threading
import time
from pathlib import Path


class R2Error(Exception):
    def __init__(self, code, status):
        super().__init__(f'R2 binding operation failed: {code}')
        self.response = {'Error': {'Code': code}, 'ResponseMetadata': {'HTTPStatusCode': status}}


class WranglerClient:
    def __init__(self):
        self.lock = threading.Lock()
        self.process = subprocess.Popen(['node', str(Path(__file__).with_name('wrangler_bridge.mjs'))],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=Path(__file__).resolve().parents[1])
        if not self._read().get('ready'):
            raise RuntimeError('Wrangler remote binding could not start')

    def _read(self):
        for line in self.process.stdout:
            if line.startswith('IWAN_RPC:'):
                return json.loads(line.removeprefix('IWAN_RPC:'))
        raise RuntimeError('Wrangler remote binding exited unexpectedly')

    def _call(self, op, args):
        for attempt in range(3):
            try:
                with self.lock:
                    return self._locked_call(op, args)
            except R2Error as error:
                if error.response['ResponseMetadata']['HTTPStatusCode'] != 502 or attempt == 2:
                    raise
                time.sleep(2 ** attempt)

    def _locked_call(self, op, args):
        self.process.stdin.write(json.dumps({'op': op, **args}) + '\n')
        self.process.stdin.flush()
        response = self._read()
        if 'code' in response:
            raise R2Error(response['code'], response['status'])
        return response['result']

    def get_object(self, **args):
        result = self._call('get', args)
        result['Body'] = io.BytesIO(base64.b64decode(result.pop('body')))
        return result

    def head_object(self, **args):
        return self._call('head', args)

    def put_object(self, **args):
        body = args.pop('Body')
        if hasattr(body, 'read'):
            body = body.read(64 * 1024 * 1024 + 1)
        if len(body) > 64 * 1024 * 1024:
            raise ValueError('Use the S3 backend for files larger than 64 MiB')
        args['body'] = base64.b64encode(body).decode()
        return self._call('put', args)

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('{"op":"close"}\n')
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(timeout=30)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                self.process.terminate()
                self.process.wait(timeout=10)
        self.process.stdout.close()
