"""Custom Implementation of Quantum Gateway lib."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import hashlib
from http import HTTPStatus
import json
import logging
from pathlib import Path
from typing import Any
import weakref

import aiofiles
import aiohttp
import aiohttp.client_exceptions
import esprima
import urllib3

TIMEOUT = aiohttp.ClientTimeout(5)

_LOGGER = logging.getLogger(__name__)


class ConnectedTo(Enum):
    """Enum for connected device types."""

    ROUTER = "br-lan"
    EXTENDER_1 = "br-lan1"
    UNKNOWN = "unknown"

    def display(self) -> str:
        """Return a human-readable string for the connected device type."""
        return {
            ConnectedTo.ROUTER: "Router",
            ConnectedTo.EXTENDER_1: "Extender",
            ConnectedTo.UNKNOWN: "???",
        }[self]


class Mobility(Enum):
    """Enum for device mobility."""

    PORTABLE = "Portable"
    STATIONARY = "Stationary"
    UNKNOWN = ""


class Port(Enum):
    """Enum for device port."""

    ATH0 = "ath0"
    ATH1 = "ath1"
    ATH11 = "ath11"
    ATH12 = "ath12"
    VETH0 = "veth0"
    VETH3 = "veth3"
    UNKNOWN = "unknown"


class ConnectionType(Enum):
    """Enum for device connection type."""

    WIFI_5_GHZ = "5G"
    WIFI_5H_GHZ = "5G_H"
    WIFI_2_4_GHZ = "2.4G"
    GUEST_2_4_GHZ = "2.4G_guest"
    IOT_2_4_GHZ = "2.4G_iot"
    ETHERNET = "Ether"
    NONE = "unknown"

    def display(self) -> str:
        """Return a human-readable string for the connection type."""
        return {
            ConnectionType.WIFI_5_GHZ: "5 GHz",
            ConnectionType.WIFI_5H_GHZ: "5 GHz (H)",
            ConnectionType.WIFI_2_4_GHZ: "2.4 GHz",
            ConnectionType.GUEST_2_4_GHZ: "2.4 GHz Guest",
            ConnectionType.IOT_2_4_GHZ: "2.4 GHz IoT",
            ConnectionType.ETHERNET: "Ethernet",
            ConnectionType.NONE: "",
        }[self]


class ConnectionInterface(Enum):
    """Enum for device connection interface."""

    UNKNOWN = ""
    ATH0 = "ath0"
    WL0 = "wl0"
    ATH1 = "ath1"
    WL1_2 = "wl1.2"
    WL0_2 = "wl0.2"
    WL0_1 = "wl0.1"
    WL2_2 = "wl2.2"
    ATH12 = "ath12"
    ATH11 = "ath11"

    def display(self) -> str:
        """Return a human-readable string for the connection interface."""
        return {
            ConnectionInterface.UNKNOWN: ConnectedTo.ROUTER,
            ConnectionInterface.ATH0: ConnectedTo.ROUTER,
            ConnectionInterface.WL0: ConnectedTo.EXTENDER_1,
            ConnectionInterface.ATH1: ConnectedTo.ROUTER,
            ConnectionInterface.WL1_2: ConnectedTo.EXTENDER_1,
            ConnectionInterface.WL0_1: ConnectedTo.UNKNOWN,
            ConnectionInterface.WL0_2: ConnectedTo.EXTENDER_1,
            ConnectionInterface.WL2_2: ConnectedTo.EXTENDER_1,
            ConnectionInterface.ATH12: ConnectedTo.ROUTER,
            ConnectionInterface.ATH11: ConnectedTo.ROUTER,
        }[self].display()


def _normalize(input: str) -> str | None:
    """Normalize input string."""
    return input if input not in {"", "(null)", "n/a"} else None


class ConnectedDevice:
    """Class to hold device information."""

    def __init__(self, data: dict[str, str]) -> None:
        """Initialize the device."""
        self._raw_data = data

    def __str__(self) -> str:
        """Return a string representation of the device."""
        return json.dumps(self._as_dict(), sort_keys=True, indent=1)

    def add_station_info(self, data: dict[str, str]):
        """Add station info to device."""
        self._raw_data = data | self._raw_data

    @staticmethod
    def headers() -> list[str]:
        """Return headers for the device."""
        return [
            "name",
            "ip",
            "mac",
            "connect_type",
            "connected_to",
            "is_connected",
            "full_state",
        ]

    def row_elements(self) -> list[str | bool | dict[str, str]]:
        """Return row elements for the device."""
        return [
            self.display_name,
            self.ip,
            self.mac,
            self.connect_type.display(),
            self.connection_interface.display(),
            self.is_connected,
            self._raw_data,
        ]

    def _as_dict(self) -> dict[str, Any]:
        return {
            "connected_to": self.connected_to.name,
            "hostname": self.hostname,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "mac": self.mac,
            "name": self.name,
            "verbose": {
                "device_type": self.device_type,
                "device_firmware": self.device_firmware,
                "device_manufacturer": self.device_manufacturer,
                "device_model": self.device_model,
                "device_sub_model": self.device_sub_model,
                "device_product": self.device_product,
                "os": self.os,
                "mac_vendor": self.mac_vendor,
                "mobility": self.mobility.name,
                "suggested_name": self.suggested_name,
                "time_first_seen": self.time_first_seen,
                "time_last_active": self.time_last_active,
                "uptime": self.uptime,
                "port": self.port.name,
                "pre_port": self.pre_port.name,
            },
        }

    @property
    def connected_to(self) -> ConnectedTo:
        """Return the device connected to."""
        return ConnectedTo(self._raw_data["bridge_port"])

    @property
    def is_connected(self) -> bool:
        """Return the device connected to."""
        return self._raw_data.get("activity", 0) == 1

    @property
    def display_name(self) -> str:
        """Return the device display name."""
        return self.name or self.hostname

    @property
    def hostname(self) -> str:
        """Return the device hostname."""
        return self._raw_data["hostname"]

    @property
    def ip(self) -> str:
        """Return the device IP address."""
        return self._raw_data["ip"]

    @property
    def mac(self) -> str:
        """Return the device MAC address."""
        return self._raw_data["mac"]

    @property
    def mac_vendor(self) -> str | None:
        """Return the device MAC vendor."""
        return _normalize(self._raw_data["mac_vendor"])

    @property
    def name(self) -> str | None:
        """Return the device name."""
        name = _normalize(self._raw_data["name"])
        return name.replace("_", " ") if name else None

    @property
    def suggested_name(self) -> str | None:
        """Return the device suggested name."""
        return _normalize(self._raw_data["suggested_name"])

    @property
    def ipv6(self) -> str | None:
        """Return the device IPv6 address."""
        return _normalize(self._raw_data["ipv6"])

    @property
    def device_type(self) -> str | None:
        """Return the device type."""
        return _normalize(self._raw_data["device"])

    @property
    def device_firmware(self) -> str | None:
        """Return the device firmware."""
        return _normalize(self._raw_data["device_firmware"])

    @property
    def device_manufacturer(self) -> str | None:
        """Return the device manufacturer."""
        return _normalize(self._raw_data["device_manufacturer"])

    @property
    def device_model(self) -> str | None:
        """Return the device model."""
        return _normalize(self._raw_data["device_model"])

    @property
    def device_sub_model(self) -> str | None:
        """Return the device sub model."""
        return _normalize(self._raw_data["device_sub_model"])

    @property
    def device_product(self) -> str | None:
        """Return the device product."""
        return _normalize(self._raw_data["device_product"])

    @property
    def os(self) -> str | None:
        """Return the device OS."""
        return _normalize(self._raw_data["device_os"])

    @property
    def mobility(self) -> Mobility:
        """Return the device mobility."""
        return Mobility(self._raw_data["mobility"])

    @property
    def time_first_seen(self) -> str:
        """Return the device first seen time."""
        return self._raw_data["time_first_seen"]

    @property
    def time_last_active(self) -> str:
        """Return the device last active time."""
        return self._raw_data["time_last_active"]

    @property
    def uptime(self) -> str:
        """Return the device uptime."""
        return self._raw_data["uptime"]

    @property
    def port(self) -> Port:
        """Return the device port."""
        return Port(self._raw_data["port"])

    @property
    def pre_port(self) -> Port:
        """Return the device pre port."""
        return Port(self._raw_data["pre_port"])

    @property
    def connect_type(self) -> ConnectionType:
        """Return the device connection type."""
        return ConnectionType(self._raw_data.get("connect_type", "unknown"))

    @property
    def connection_interface(self) -> ConnectionInterface:
        """Return the device connection interface."""
        return ConnectionInterface(self._raw_data.get("connect_intf", ""))


def _encode_luci_string(unencoded_string):
    """Encode a string to be sent to a G3100 gateway in a "luci_" POST parameter."""
    md5_hash = hashlib.md5(unencoded_string.encode("ascii")).hexdigest()
    return hashlib.sha512(md5_hash.encode("ascii")).hexdigest()


def _encode_luci_password(unencoded_string, token):
    """Encode a string to be sent to a G3100 gateway in a "luci_" POST parameter."""
    md5_hash = hashlib.md5(unencoded_string.encode("ascii")).hexdigest()
    sha_hash = hashlib.sha512(md5_hash.encode("ascii")).hexdigest()
    return hashlib.sha512((token + sha_hash).encode("ascii")).hexdigest()


class Gateway(ABC):
    """Gateway class."""

    def __init__(
        self, local_only: bool | None = None, cache_dir: Path | None = None
    ) -> None:
        """Initialize the gateway."""
        super().__init__()

        self.connected_devices: dict[str, ConnectedDevice] = {}
        self.success_init = False
        self._local_only = local_only
        self._cache_dir = cache_dir

    @abstractmethod
    async def check_auth(self) -> bool:
        """Attempt to authenticate with the device.

        Returns whether or not authentication succeeded.
        """

    @abstractmethod
    async def close_connection(self):
        """Close the connection."""

    @abstractmethod
    async def get_connected_devices(self) -> dict[str, ConnectedDevice]:
        """Get the connected devices as a MAC address -> hostname map."""

    def get_cache_file(self) -> Path | None:
        """Return the cache file path."""
        if self._cache_dir:
            self._cache_dir.mkdir(exist_ok=True, parents=True)
            return self._cache_dir / "log.json"
        return None


class Gateway3100(Gateway):
    """Gateway3100 class."""

    def __init__(
        self,
        host: str,
        password: str,
        local_only: bool | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        """Initialize the gateway."""
        super().__init__(local_only, cache_dir)

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.verify = False
        self.host = "https://" + host
        self.username = "admin"
        self.password = password
        self.token = ""
        self.loginToken = ""

        self.session = aiohttp.ClientSession()

        # Attempt to log out when this object is destroyed.
        if not self._local_only:
            weakref.finalize(
                self,
                self.session.post,
                self.host + "/logout.cgi",
                timeout=TIMEOUT,
                ssl=self.verify,
                data={"token": self.token},
            )

    def __del__(self):
        """Destroy the session."""
        # self.close_connection()

    async def close_connection(self):
        """Close the connection."""
        _LOGGER.info("Destroying Gateway client session")
        await self.session.close()

    @classmethod
    async def is_valid_host(cls, host):
        """Check if the host is a valid host."""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        async with aiohttp.ClientSession() as session:
            return (
                await session.get(
                    "https://" + host + "/loginStatus.cgi",
                    verify=False,
                    timeout=TIMEOUT,
                ).status
                != HTTPStatus.NOT_FOUND
            )

    async def get_connected_devices(self):
        """Get connected devices."""
        if self._local_only:

            @dataclass
            class Ret:
                status: HTTPStatus
                text: str

            async with aiofiles.open(self.get_cache_file()) as f:
                data = await f.read()
                result = json.loads(data)
                res = Ret(status=result["status_code"], text=result["text"])
        else:
            res = await self.session.get(
                self.host + "/cgi/cgi_owl.js", timeout=TIMEOUT, ssl=self.verify
            )
            if (cache_file := self.get_cache_file()) is not None:
                with cache_file.open("w") as f:
                    data = await res.text()
                    json.dump(
                        {"text": data, "status_code": res.status},
                        f,
                        indent=True,
                        sort_keys=True,
                    )

        if res.status != HTTPStatus.OK:
            _LOGGER.warning(
                "Failed to get connected devices from gateway; "
                "got HTTP status code %s",
                res.status,
            )

        connected_devices = {}

        # Unfortunately, the data is provided to the frontend not as a JSON
        # blob, but as some JavaScript to execute.  The below code uses a
        # JavaScript parser and AST visitor to extract the known device data
        # from the script.
        #
        # Example response:
        #
        # addROD('known_device_list', { 'known_devices': [ { 'mac': 'xx:xx:xx:xx:xx:xx', 'hostname': 'name' } ] });
        def visitor(node, metadata):
            if node.type != "CallExpression":
                return

            if node.callee.type != "Identifier" or node.callee.name != "addROD":
                return

            if node.arguments[0].value == "known_device_list":
                known_devices_node = None
                for prop in node.arguments[1].properties:
                    if prop.key.value == "known_devices":
                        known_devices_node = prop.value

                if known_devices_node is None:
                    _LOGGER.debug(
                        "Failed to find known_devices object in response data"
                    )
                    return

                for device in known_devices_node.elements:
                    data = {
                        prop.key.value: prop.value.value for prop in device.properties
                    }
                    if (
                        "activity" not in data
                        or "mac" not in data
                        or "hostname" not in data
                    ):
                        continue
                    # if data["activity"] == 1:
                    connected_devices[data["mac"]] = ConnectedDevice(data)
                    # else:
                    #     print(json.dumps(data, indent=1, sort_keys=True))
            elif node.arguments[0].value == "dump_toplogy_station_info":
                stations_node = None
                for prop in node.arguments[1].properties:
                    if prop.key.value == "stations":
                        stations_node = prop.value

                if stations_node is None:
                    _LOGGER.debug("Failed to find stations object in response data")
                    return

                for device in stations_node.elements:
                    data = {
                        prop.key.value: prop.value.value for prop in device.properties
                    }
                    if "station_mac" not in data:
                        continue
                    mac_addr = data["station_mac"].lower()
                    if mac_addr not in connected_devices:
                        continue
                    connected_devices[mac_addr].add_station_info(data)

        if isinstance(res.text, str):
            text = res.text
        else:
            text = await res.text()
        lines = text.split("\n")
        known_device_list = ""
        dump_toplogy_station_info = ""
        for line in lines:
            if "known_device_list" in line:
                known_device_list = line
            if "dump_toplogy_station_info" in line:
                dump_toplogy_station_info = line
        esprima.parseScript(known_device_list, {}, visitor)
        esprima.parseScript(dump_toplogy_station_info, {}, visitor)

        return connected_devices

    async def _check_login_status(self):
        if self._local_only:
            return True
        res = await self.session.get(
            self.host + "/loginStatus.cgi", timeout=TIMEOUT, ssl=self.verify
        )
        if res.status == HTTPStatus.OK:
            _text = await res.text()
            json_res = json.loads(_text)
            self.loginToken = json_res["loginToken"]
            if json_res["islogin"] == "1":
                # Store the XSRF token for use in future requests.
                self.token = json_res["token"]
                return True
        _LOGGER.warning(f"{res.status}: {res.reason}")  # noqa: G004
        return False

    async def _attempt_old_login(self):
        body = {
            "luci_username": _encode_luci_string(self.username),
            "luci_password": _encode_luci_string(self.password),
        }
        try:
            res = await self.session.post(
                self.host + "/login.cgi", timeout=TIMEOUT, data=body, ssl=self.verify
            )
        except aiohttp.client_exceptions.ClientConnectorError:
            return False

        return await self._check_login_success(res)

    async def _attempt_new_login(self):
        body = {
            "luci_username": _encode_luci_string(self.username),
            "luci_password": _encode_luci_password(self.password, self.loginToken),
            "luci_token": self.loginToken,
        }
        res = await self.session.post(
            self.host + "/login.cgi", timeout=TIMEOUT, data=body, ssl=self.verify
        )
        return await self._check_login_success(res)

    async def _check_login_success(self, res: aiohttp.ClientResponse):
        if res.status in (HTTPStatus.OK, HTTPStatus.FOUND):
            return await self._check_login_status()

        if res.status == HTTPStatus.FORBIDDEN:
            text = await res.text()
            response_json = json.loads(text)
            if response_json.get("flag") == 2:
                _LOGGER.warning(
                    "Hit maximum session limit of %s sessions",
                    response_json["maxsession"],
                )

        else:
            _LOGGER.debug("unexpected response code: %s", res.status)
        return False

    async def check_auth(self):
        """Check authentication."""
        if await self._check_login_status():
            return True

        if await self._attempt_old_login():
            return True

        return await self._attempt_new_login()


class QuantumGatewayScanner:
    """Quantum Gateway Scanner."""

    def __init__(
        self,
        host: str,
        password: str,
        local_only: bool = False,
        cache_dir: Path | None = None,
    ) -> None:
        """Initialize the scanner."""
        if local_only and cache_dir is None:
            error_message = "'cache_dir' must be specified if using 'local_only'"
            _LOGGER.fatal(error_message)
            raise AssertionError(error_message)
        self._local_only = local_only
        self._cache_dir = cache_dir
        self.connected_devices: dict[str, ConnectedDevice] = {}

        self._gateway = self._get_gateway(host, password)
        self.success_init = self._gateway.check_auth()

    def _get_gateway(self, host, password) -> Gateway:
        if self._local_only:
            return Gateway3100(host, password, self._local_only, self._cache_dir)
        return Gateway3100(host, password, self._local_only, self._cache_dir)
        # if await Gateway3100.is_valid_host(host):
        #     return Gateway3100(host, password, self._local_only, self._cache_dir)
        # raise NotImplementedError

    async def close_connection(self):
        """Close the connection."""
        await self._gateway.close_connection()

    async def scan_devices(self) -> list[str]:
        """Scan for new devices and return a list of found MACs."""
        self.connected_devices = {}
        if await self._gateway.check_auth():
            self.connected_devices = await self._gateway.get_connected_devices()
        return list(self.connected_devices.keys())

    def get_device_name(self, device: str) -> str | None:
        """Return the name of the given device or None if we don't know."""
        return (
            self.connected_devices[device].name
            if device in self.connected_devices
            else None
        )
