"""Support for Verizon FiOS Quantum Gateways."""

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from . import QuantumGatewayConfigEntry
from .lib import ConnectedTo, ConnectionType, QuantumGatewayScanner


@dataclass(frozen=True, kw_only=True)
class QuantumGatewaySensorDescription(SensorEntityDescription):
    """Describe Quantum Gateway sensor entity."""

    value_fn: Callable[[QuantumGatewayScanner], int | float]


ALL_SENSORS: tuple[QuantumGatewaySensorDescription, ...] = (
    QuantumGatewaySensorDescription(
        key="connected_devices",
        value_fn=lambda x: sum(
            1 for x in x.connected_devices.values() if x.is_connected
        ),
    ),
    QuantumGatewaySensorDescription(
        key="inactive_devices",
        value_fn=lambda x: sum(
            1 for x in x.connected_devices.values() if not x.is_connected
        ),
    ),
    QuantumGatewaySensorDescription(
        key="total_devices_tracked", value_fn=lambda x: len(x.connected_devices)
    ),
    QuantumGatewaySensorDescription(
        key="count_5g",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connect_type
            in {
                ConnectionType.WIFI_5_GHZ,
                ConnectionType.WIFI_5H_GHZ,
            }
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_2.4g",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connect_type
            in {
                ConnectionType.WIFI_2_4_GHZ,
            }
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_2.4g_all",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connect_type
            in {
                ConnectionType.WIFI_2_4_GHZ,
                ConnectionType.GUEST_2_4_GHZ,
                ConnectionType.IOT_2_4_GHZ,
            }
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_iot",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connect_type
            in {
                ConnectionType.IOT_2_4_GHZ,
            }
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_guest",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connect_type
            in {
                ConnectionType.GUEST_2_4_GHZ,
            }
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_router",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connection_interface.display() == ConnectedTo.ROUTER.display()
        ),
    ),
    QuantumGatewaySensorDescription(
        key="count_extender",
        value_fn=lambda x: sum(
            1
            for x in x.connected_devices.values()
            if x.is_connected
            and x.connection_interface.display() == ConnectedTo.EXTENDER_1.display()
        ),
    ),
)


@dataclass(frozen=True)
class _SensorMetadata:
    unique_id: str | None
    description: QuantumGatewaySensorDescription


async def async_setup_entry(
    hass: HomeAssistant,
    entry: QuantumGatewayConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensors."""
    router = entry.runtime_data
    entities = [
        QuantumGatewaySensor(
            router,
            _SensorMetadata(unique_id=entry.unique_id, description=description),
        )
        for description in ALL_SENSORS
    ]
    async_add_entities(entities, True)


class QuantumGatewaySensor(SensorEntity):
    """Representation of a Quantum Gateway sensor."""

    def __init__(
        self,
        router: QuantumGatewayScanner,
        metadata: _SensorMetadata,
    ) -> None:
        """Initialize the sensor."""
        self._router = router
        self._metadata = metadata

        self._attr_has_entity_name = True
        self._attr_unique_id = slugify(
            f"{metadata.unique_id}_{metadata.description.key}"
        )

    async def async_update(self) -> None:
        """Update the state of the sensor."""
        await self._router.scan_devices()

    @property
    def native_value(self) -> int | float:
        """Return the state of the sensor."""
        return self._metadata.description.value_fn(self._router)
