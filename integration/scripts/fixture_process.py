# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run disposable integration clients only while their required node is alive."""
import os
import signal
import subprocess
import time


def install_termination_handler():
    """Let Python fixture finally blocks close PTY sessions on supervisor TERM."""
    def terminate(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)


def stop_group(child):
    """The caller owns this newly created process group, including local provers."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    # A parent can exit before a descendant which ignores TERM. Never leave that
    # descendant proving after a failed fixture or a parent timeout.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()


def run_monitored(command, peer, *, timeout, env=None, capture_stdout=False):
    """Return CompletedProcess; node exit and timeout raise after group cleanup.

    communicate() drains captured output during each short wait. Retrying it after
    TimeoutExpired preserves the complete stream without duplicating prefixes.
    """
    if timeout <= 0:
        raise ValueError('Fixture timeout must be positive')
    if peer.poll() is not None:
        raise RuntimeError(f'Required sequencer already exited with status {peer.returncode}')
    child = subprocess.Popen(command, env=env, text=True,
                             stdout=subprocess.PIPE if capture_stdout else None,
                             start_new_session=True)
    deadline = time.monotonic() + timeout
    try:
        while True:
            if peer.poll() is not None:
                raise RuntimeError(f'Required sequencer exited with status {peer.returncode} while client was running')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                stdout, stderr = child.communicate(timeout=min(0.5, remaining))
                if peer.poll() is not None:
                    raise RuntimeError(f'Required sequencer exited with status {peer.returncode} before client completion')
                return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    finally:
        stop_group(child)
