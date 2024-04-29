from __future__ import annotations

import datetime as dt
import enum
import re
import subprocess
from dataclasses import dataclass

from dateutil.parser import parse as dt_parse


class MullvadError(Exception):
    pass


class FailedToParseOutput(MullvadError):
    pass


class StatusName(enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    DISCONNECTING = "disconnecting"


@dataclass
class Status:
    connected: bool
    status: StatusName
    server_name: str | None = None
    location: str | None = None
    ipv4: str | None = None
    position: str | None = None


@dataclass
class Account:
    token: str
    expiration: dt.datetime


@dataclass
class Relay:
    country: str
    country_code: str
    city: str
    city_code: str
    location: str
    hostname: str
    ipv4: str
    ipv6: str | None
    protocol: str
    provider: str
    ownership: str


class Mullvad:
    @classmethod
    def get_account(cls) -> Account:
        output, _ = cls._execute(["mullvad", "account", "get"])
        output_dict = cls._parse_key_value_output(output)
        return Account(output_dict["mullvad account"], dt_parse(output_dict["expires at"]))

    @classmethod
    def lockdown_mode(cls, new_value: bool | None = None) -> bool:
        if new_value is not None:
            policy = "on" if new_value else "off"
            # TODO: check output
            cls._execute(["mullvad", "lockdown-mode", "set", policy])
            return new_value
        output, _ = cls._execute(["mullvad", "lockdown-mode", "get"])
        if "traffic will be allowed" in output:
            return False
        if "traffic will be blocked":
            return True
        raise FailedToParseOutput(repr(output))

    @classmethod
    def status(cls, full: bool = False) -> Status:
        location_arg = ["--location"] if full else []
        output, _ = cls._execute(["mullvad", "status", *location_arg])
        tunnel_status = output.split("\n", 1)[0].strip()
        strict = False if full and "location data unavailable" in output.lower() else True
        parsed = cls._parse_key_value_output(output.split("\n", 1)[1], strict)
        if (
            disconnected := "disconnected" in tunnel_status.lower()
        ) or "disconnecting" in tunnel_status.lower():
            status = StatusName.DISCONNECTED if disconnected else StatusName.DISCONNECTING
            return Status(
                connected=False,
                status=status,
                ipv4=parsed.get("ipv4", None),
                position=parsed.get("position", None),
            )

        status_pattern = re.compile(
            r"^((?:Connected)|(?:Connecting)) to ([a-zA-Z0-9\-]+) in ([\w \,\-]+)(?:\.\.\.)?$"
        )
        match status_pattern.match(tunnel_status):
            case re.Match() as m:
                return Status(
                    connected=(m.group(1).lower() == StatusName.CONNECTED.value),
                    status=StatusName(m.group(1).lower()),
                    server_name=m.group(2),
                    location=m.group(3),
                    ipv4=parsed.get("ipv4", None),
                    position=parsed.get("position", None),
                )
            case _:
                raise FailedToParseOutput(repr(tunnel_status))

    @classmethod
    def connect(cls, wait: bool = True) -> None:
        cls._connection_change("connect", wait)

    @classmethod
    def disconnect(cls, wait: bool = True) -> None:
        cls._connection_change("disconnect", wait)

    @classmethod
    def reconnect(cls, wait: bool = True) -> None:
        cls._connection_change("reconnect", wait)

    @staticmethod
    def _parse_relay_list_country_line(line: str) -> tuple[str, str]:
        country_re = re.compile(r"^([\w ]+) \(([a-z]+)\)$")
        match country_re.match(sl := line.strip()):
            case re.Match() as m:
                return tuple(m.groups())
            case _:
                raise FailedToParseOutput(repr(sl))

    @staticmethod
    def _parse_relay_list_city_line(line: str) -> tuple[str, str, str]:
        city_re = re.compile(
            r"^([\w\,\[\] ]+) \(([a-z]+)\) \@ (\-?\d+\.\d+\°N\, \-?\d+\.\d+\°W)$"
        )
        match city_re.match(sl := line.strip()):
            case re.Match() as m:
                return tuple(m.groups())
            case _:
                raise FailedToParseOutput(sl)

    @staticmethod
    def _parse_relay_list_server_line(line: str) -> tuple[str, str, str, str, str, str]:
        server_re = re.compile(
            r"^([a-z0-9\-]+) \(([0-9\.]+)(?:, ([0-9a-f\:]+))?\) \- ([a-zA-Z]+)\, hosted by"
            r" ([a-zA-Z0-9]+) \(((?:rented)|(?:Mullvad-owned))\)$"
        )
        match server_re.match(sl := line.strip()):
            case re.Match() as m:
                return tuple(m.groups())
            case _:
                raise FailedToParseOutput(sl)

    @classmethod
    def relay_list(cls) -> list[Relay]:
        output, _ = cls._execute(["mullvad", "relay", "list"])
        country = city = None
        relays: list[Relay] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            leading_tabs = len(line[: len(line) - len(line.lstrip("\t"))])
            match leading_tabs:
                case 0:  # Country line
                    country = cls._parse_relay_list_country_line(line)
                case 1:  # City line
                    city = cls._parse_relay_list_city_line(line)
                case 2:  # Server line
                    (
                        hostname,
                        ipv4,
                        ipv6,
                        protocol,
                        provider,
                        ownership,
                    ) = cls._parse_relay_list_server_line(line)
                    if country is None:
                        raise FailedToParseOutput(f"No country before line: {line!r}")
                    if city is None:
                        raise FailedToParseOutput(f"No city before line: {line!r}")
                    relays.append(
                        Relay(
                            country=country[0],
                            country_code=country[1],
                            city=city[0],
                            city_code=city[1],
                            location=city[2],
                            hostname=hostname,
                            ipv4=ipv4,
                            ipv6=ipv6,
                            protocol=protocol,
                            provider=provider,
                            ownership=ownership,
                        )
                    )
                case _:
                    raise FailedToParseOutput(repr(line))
        return relays

    @classmethod
    def update_relays(cls) -> None:
        # TODO: Check output
        cls._execute(["mullvad", "relay", "update"])

    @classmethod
    def set_relay(cls, relay: Relay | str) -> None:
        match relay:
            case Relay(hostname=hostname) | str(hostname):
                cls._set_relay(hostname)
            case _:
                raise MullvadError(f"unexpected relay: f{relay!r}")

    @classmethod
    def _set_relay(cls, hostname: str):
        # TODO: Catch error for no matching server
        cls._execute(["mullvad", "relay", "set", "location", hostname])

    @classmethod
    def _connection_change(cls, change_cmd: str, wait: bool) -> None:
        wait_param = ["--wait"] if wait else []
        cls._execute(["mullvad", change_cmd, *wait_param])

    @staticmethod
    def _execute(cmd: list[str]) -> tuple[str, str]:
        # TODO: add timeout
        proc = subprocess.run(cmd, capture_output=True, shell=False, check=True)
        return proc.stdout.decode(), proc.stderr.decode()

    @staticmethod
    def _parse_key_value_output(output: str, strict: bool = True) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in output.strip().splitlines():
            split_line = line.split(":", 1)
            if len(split_line) != 2:
                if strict:
                    raise FailedToParseOutput(output)
                continue
            result[split_line[0].strip().lower()] = split_line[1].strip()
        return result
