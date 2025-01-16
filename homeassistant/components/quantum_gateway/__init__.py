"""The quantum_gateway component."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant

from .lib import QuantumGatewayScanner

QuantumGatewayConfigEntry = ConfigEntry[QuantumGatewayScanner]
PLATFORMS = [Platform.DEVICE_TRACKER, Platform.SENSOR]


async def async_setup_entry(
    hass: HomeAssistant, entry: QuantumGatewayConfigEntry
) -> bool:
    """Set up Fios platform."""

    assert "host" in entry.data
    assert "password" in entry.data

    router = QuantumGatewayScanner(entry.data["host"], entry.data["password"])
    if not await router.success_init:
        return False

    # to do: Re-enable this when async_on_close is available
    # router.async_on_close(entry.add_update_listener(update_listener))

    async def async_close_connection(event: Event) -> None:
        """Close Fios connection on HA Stop."""
        await router.close_connection()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, async_close_connection)
    )

    entry.runtime_data = router

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: QuantumGatewayConfigEntry
) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        router = entry.runtime_data
        await router.close_connection()

    return unload_ok


async def update_listener(
    hass: HomeAssistant, entry: QuantumGatewayConfigEntry
) -> None:
    """Update when config_entry options update."""
    # to do: figure out if/how to handle options + updates

    # router = entry.runtime_data
    # if router.update_options(entry.options):
    #     await hass.config_entries.async_reload(entry.entry_id)
