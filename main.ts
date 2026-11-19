// Cobalt Forge entrypoint: launches the static native C++ epoll forge binary,
// registers its bound ephemeral port with $MAKEFUN_ENV_URL/register, and polls
// $MAKEFUN_ENV_URL/done until the trial completes.

import { spawn, type ChildProcess } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (ENV_URL === '') {
  process.stderr.write('[cobalt-forge] MAKEFUN_ENV_URL is not set\n');
  process.exit(1);
}

const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 100;
const RETRY_MAX_MS = 2_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

function startForgeBinary(): Promise<{ child: ChildProcess; port: number }> {
  const dir = dirname(fileURLToPath(import.meta.url));
  const binPath = join(dir, 'bin', 'forge');
  return new Promise((resolve, reject) => {
    const child = spawn(binPath, [], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    let stdoutBuf = '';
    let settled = false;

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    child.once('error', (err) => fail(err));
    child.once('exit', (code, sig) => fail(new Error(`forge exited before binding port (code=${String(code)}, sig=${String(sig)})`)));
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      if (settled) return;
      stdoutBuf += chunk;
      const nl = stdoutBuf.indexOf('\n');
      if (nl < 0) return;
      const line = stdoutBuf.slice(0, nl).trim();
      const match = /^PORT\s+(\d+)$/.exec(line);
      if (!match) {
        fail(new Error(`unexpected port line from forge: ${JSON.stringify(line)}`));
        return;
      }
      const port = Number(match[1]);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        fail(new Error(`invalid port from forge: ${line}`));
        return;
      }
      settled = true;
      resolve({ child, port });
    });
  });
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone(): Promise<void> {
  for (;;) {
    await sleep(1_500);
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // retry on transient errors
    }
  }
}

async function main(): Promise<void> {
  const { child, port } = await startForgeBinary();
  process.stdout.write(`[cobalt-forge] native forge listening on port ${port}\n`);

  const shutdown = (): void => {
    if (!child.killed) child.kill('SIGTERM');
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  await register(port);
  process.stdout.write('[cobalt-forge] registered; waiting for done\n');

  await waitForDone();
  shutdown();
  await Promise.race([
    new Promise<void>((resolve) => child.once('exit', () => resolve())),
    sleep(1_000),
  ]);
  process.stdout.write('[cobalt-forge] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[cobalt-forge] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
