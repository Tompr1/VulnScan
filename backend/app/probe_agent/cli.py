"""
The ``v0cday-probe`` command.

    v0cday-probe enroll --platform https://soc.example --token <token>
    v0cday-probe run
    v0cday-probe status
    v0cday-probe desired-image    (for the appliance's updater)

Exit codes: 0 ok, 1 error, 2 the platform rejects this probe (revoked, or
enrolled again elsewhere): enroll it again with a new token from Root.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import socket
import sys
from collections.abc import Mapping
from pathlib import Path

from app.core.config import settings
from app.probe_agent.agent import FixedAllowlist, ProbeAgent, RemoteCancellation, ReportOutbox
from app.probe_agent.config import DEFAULT_CONFIG_PATH, ConfigError, ProbeConfig, check_platform_url
from app.probe_agent.platform import PlatformClient, PlatformError, ProbeRejected, open_http
from app.probe_agent.reference import RemoteReferenceData
from app.scan_jobs.executors import EngineScanExecutor, ScanExecutor, StandaloneScanExecutor, new_api_scanner
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.budget import ScanBudget
from app.scanner.engine import ScanEngine
from app.scanner.plugins.loader import builtin_registry
from app.scanner.target import ScanType

logger = logging.getLogger("v0cday.probe")

EXIT_OK, EXIT_ERROR, EXIT_REJECTED = 0, 1, 2


def probe_executors(allowlist: AllowlistPolicy, cancellation: RemoteCancellation) -> Mapping[ScanType, ScanExecutor]:
    """What a probe runs: network scans with the scan engine, and API scans.
    IaC and inventory jobs never reach a probe."""
    engine = ScanEngine(
        registry=builtin_registry(),
        allowlist=FixedAllowlist(allowlist),
        budget=ScanBudget(total_seconds=float(settings.SCAN_BUDGET_SECONDS)),
        request_timeout_seconds=float(settings.SCAN_TIMEOUT_SECONDS),
        cancellation=cancellation,
    )
    network = EngineScanExecutor(lambda: engine)
    return {
        ScanType.INTERNAL: network,
        ScanType.EXTERNAL: network,
        ScanType.API: StandaloneScanExecutor("api_scanner_config", new_api_scanner),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="v0cday-probe", description="v0cday scan probe")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help=f"default: {DEFAULT_CONFIG_PATH}")
    parser.add_argument("-v", "--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser("enroll", help="enroll this probe with a one-time token from Root > Scan probes")
    enroll.add_argument("--platform", required=True, help="platform URL, e.g. https://soc.example")
    enroll.add_argument("--token", default=os.environ.get("V0CDAY_ENROLL_TOKEN"),
                        help="one-time token (or V0CDAY_ENROLL_TOKEN, which keeps it out of the process list)")
    enroll.add_argument("--ca-bundle", help="CA certificate(s) to trust the platform with")
    enroll.add_argument("--allow-http", action="store_true", help="lab only: platform over plain HTTP")
    enroll.add_argument("--local-allowlist", help="the client's own limit on what this probe scans (ALLOWLIST syntax)")

    run = commands.add_parser("run", help="take and run the client's scans until stopped")
    run.add_argument("--once", action="store_true", help="run at most one job, then exit")
    commands.add_parser("status", help="check the configuration and the connection to the platform")
    commands.add_parser("desired-image", help="print the probe image the platform asks for (empty: keep the current one)")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        return {"enroll": _enroll, "run": _run, "status": _status, "desired-image": _desired_image}[args.command](args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ProbeRejected as exc:
        print(f"error: the platform rejects this probe ({exc}). Enroll it again with a new token "
              "from Root > Scan probes.", file=sys.stderr)
        return EXIT_REJECTED
    except PlatformError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _enroll(args: argparse.Namespace) -> int:
    if not args.token:
        raise ConfigError("No enrollment token: pass --token or set V0CDAY_ENROLL_TOKEN")
    check_platform_url(args.platform, args.allow_http)
    if args.local_allowlist:
        AllowlistPolicy.from_setting(args.local_allowlist)  # invalid entries are logged here
    with open_http(args.platform, args.ca_bundle) as http:
        enrolled = PlatformClient(http, None, settings.PLATFORM_VERSION).enroll(args.token, socket.gethostname())
    config = ProbeConfig(
        platform_url=args.platform.rstrip("/"),
        credential=enrolled.credential,
        probe_id=enrolled.probe_id,
        workspace_id=enrolled.workspace_id,
        name=enrolled.name,
        ca_bundle=args.ca_bundle,
        allow_http=args.allow_http,
        local_allowlist=args.local_allowlist,
    )
    config.save(args.config)
    print(f"Probe #{enrolled.probe_id} '{enrolled.name}' enrolled for client #{enrolled.workspace_id}. "
          f"Configuration saved to {args.config}. Start it with: v0cday-probe run")
    return EXIT_OK


def _run(args: argparse.Namespace) -> int:
    config = ProbeConfig.load(args.config)
    state = Path(config.state_dir)
    stopping = asyncio.Event()

    async def run() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stopping.set)
        with _http(config) as http:
            client = PlatformClient(http, config.authorization, settings.PLATFORM_VERSION)
            await asyncio.to_thread(client.heartbeat, socket.gethostname())
            agent = ProbeAgent(client, RemoteReferenceData(client, state / "reference"), probe_executors,
                               ReportOutbox(state / "outbox"), config.local_allowlist)
            logger.info("Probe #%d '%s' started (platform %s)", config.probe_id, config.name, config.platform_url)
            if args.once:
                await agent.run_once()
            else:
                await agent.run_forever(stopping.is_set)
            logger.info("Probe stopped")

    asyncio.run(run())
    return EXIT_OK


def _status(args: argparse.Namespace) -> int:
    config = ProbeConfig.load(args.config)
    with _http(config) as http:
        answer = PlatformClient(http, config.authorization, settings.PLATFORM_VERSION).heartbeat(socket.gethostname())
    print(f"Probe #{answer['probe_id']} '{config.name}' of client #{answer['workspace_id']}: "
          f"connected to {config.platform_url} (platform time {answer['server_time']})."
          + (f" Local scope: {config.local_allowlist}." if config.local_allowlist else ""))
    return EXIT_OK


def _desired_image(args: argparse.Namespace) -> int:
    """Prints only the image reference (or nothing), for scripts."""
    config = ProbeConfig.load(args.config)
    with _http(config) as http:
        answer = PlatformClient(http, config.authorization, settings.PLATFORM_VERSION).heartbeat(socket.gethostname())
    print(answer.get("desired_image") or "")
    return EXIT_OK


def _http(config: ProbeConfig):
    return open_http(config.platform_url, config.ca_bundle, config.client_cert, config.client_key)
