"""Support for Verizon FiOS Quantum Gateways."""

from __future__ import annotations

from datetime import datetime, timedelta
import logging

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.core import HomeAssistant, ServiceCall, callback

# from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

# from homeassistant.helpers.typing import ConfigType
from . import QuantumGatewayConfigEntry
from .const import DEFAULT_UPDATE_INTERVAL_MINUTES, DOMAIN, SERVICE_UPDATE_ROUTER
from .lib import ConnectedDevice, ConnectionType, QuantumGatewayScanner

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: QuantumGatewayConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for AsusWrt component."""
    router = entry.runtime_data
    tracked: set = set()

    # to do: Re-enable this when async_on_close is available
    # router.async_on_close(
    #     async_dispatcher_connect(hass, router.signal_device_new, update_router)
    # )
    async def update_router(date: datetime | None = None) -> None:
        """Update the values of the router."""
        await router.scan_devices()
        add_entities(router, async_add_entities, tracked)

    async def update_router_service(call: ServiceCall | None = None) -> None:
        """Update the values of the router."""
        await update_router()

    entry.async_on_unload(
        async_track_time_interval(
            hass, update_router, timedelta(minutes=DEFAULT_UPDATE_INTERVAL_MINUTES)
        )
    )
    hass.services.async_register(DOMAIN, SERVICE_UPDATE_ROUTER, update_router_service)

    await update_router()


@callback
def add_entities(
    router: QuantumGatewayScanner,
    async_add_entities: AddEntitiesCallback,
    tracked: set[str],
) -> None:
    """Add new tracker entities from the router."""
    new_tracked = []

    for mac, device in router.connected_devices.items():
        if mac in tracked:
            continue

        new_tracked.append(QuantumGatewayDeviceEntity(device))
        tracked.add(mac)

    async_add_entities(new_tracked)


class QuantumGatewayDeviceEntity(ScannerEntity):
    """Represent a tracked device."""

    def __init__(self, device: ConnectedDevice) -> None:
        """Initialize the device."""
        super().__init__()
        self._device = device
        self.has_entity_name = True
        self.name = self.hostname

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Disable entity registry by default."""
        return True

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        return self._device.is_connected

    @property
    def hostname(self) -> str:
        """Return the hostname of the device."""
        return self._device.display_name

    @property
    def ip_address(self) -> str:
        """Return the primary ip address of the device."""
        return self._device.ip

    @property
    def mac_address(self) -> str:
        """Return the mac address of the device."""
        return self._device.mac

    @property
    def source_type(self) -> SourceType:
        """Return the source type of the device."""
        return SourceType.ROUTER

    @property
    def extra_state_attributes(self) -> dict[str, str | bool | dict[str, str]]:
        """Return the state attributes."""
        return dict(
            zip(ConnectedDevice.headers(), self._device.row_elements(), strict=True)
        )

    @property
    def icon(self) -> str:
        """Return device icon."""
        connection_type = self._device.connect_type
        if connection_type == ConnectionType.ETHERNET:
            return "mdi:ethernet"
        if connection_type in {
            ConnectionType.WIFI_5_GHZ,
            ConnectionType.WIFI_5H_GHZ,
        }:
            return "mdi:wifi-plus"
        if connection_type == ConnectionType.WIFI_2_4_GHZ:
            return "mdi:wifi-minus"
        if connection_type == ConnectionType.GUEST_2_4_GHZ:
            return "mdi:wifi-marker"
        if connection_type == ConnectionType.IOT_2_4_GHZ:
            return "mdi:wifi-cog"

        _LOGGER.warning(f"Unknown connection type {connection_type.name}")  # noqa: G004
        return "mdi:lan-disconnect"
