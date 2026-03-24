"""Hook-based DNS provider for DNS-01 challenges.

Delegates record creation and deletion to external scripts invoked via
:func:`asyncio.create_subprocess_exec`.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import shutil

logger = logging.getLogger("lacme.challenges.providers.hook")


class HookDNSProvider:
    """DNS provider that calls external scripts for record management.

    Satisfies :class:`~lacme.challenges.dns01.DNSProvider`.

    Commands receive the domain and TXT record value as positional arguments.
    If a command is provided as a string it is split using :func:`shlex.split`.
    """

    def __init__(
        self,
        *,
        create_command: str | list[str],
        delete_command: str | list[str],
        timeout: float = 30.0,
    ) -> None:
        self._create_command = self._normalize_command(create_command)
        self._delete_command = self._normalize_command(delete_command)
        self._timeout = timeout
        # Validate commands are non-empty and executables exist
        for label, cmd in [("create", self._create_command), ("delete", self._delete_command)]:
            if not cmd:
                msg = f"Hook {label} command must be non-empty"
                raise ValueError(msg)
            if shutil.which(cmd[0]) is None:
                msg = f"Hook {label} command not found: {cmd[0]!r}"
                raise FileNotFoundError(msg)

    async def create_txt_record(self, domain: str, value: str) -> None:
        """Run the create hook with *domain* and *value* as arguments."""
        await self._run(self._create_command, domain, value)

    async def delete_txt_record(self, domain: str, value: str) -> None:
        """Run the delete hook with *domain* and *value* as arguments."""
        await self._run(self._delete_command, domain, value)

    async def _run(self, command: list[str], domain: str, value: str) -> None:
        cmd = [*command, domain, value]
        logger.debug("Running hook: %s", cmd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            msg = f"Hook command timed out after {self._timeout}s: {cmd}"
            raise RuntimeError(msg) from None

        if proc.returncode != 0:
            msg = (
                f"Hook command failed with exit code {proc.returncode}: {cmd}\n"
                f"stderr: {stderr.decode('utf-8', errors='replace')}"
            )
            raise RuntimeError(msg)

        logger.debug("Hook completed successfully: %s", cmd)

    @staticmethod
    def _normalize_command(command: str | list[str]) -> list[str]:
        if isinstance(command, str):
            return shlex.split(command)
        return list(command)
