"""The tests for the filesize sensor."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant.components.filesize.const import DOMAIN
from homeassistant.const import CONF_FILE_PATH, STATE_UNAVAILABLE, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.entity_component import async_update_entity

from . import TEST_FILE_NAME, async_create_file

from tests.common import MockConfigEntry, snapshot_platform


@pytest.mark.parametrize(
    "load_platforms",
    [[Platform.SENSOR]],
)
@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_sensors(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    tmp_path: Path,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test that an invalid path is caught."""
    testfile = str(tmp_path.joinpath("file.txt"))
    await async_create_file(hass, testfile)
    hass.config.allowlist_external_dirs = {tmp_path}
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry, data={CONF_FILE_PATH: testfile}
    )
    with (
        patch(
            "os.stat_result.st_mtime",
            1732126764.780758,
        ),
        patch(
            "os.stat_result.st_ctime",
            1732126744.780758,
        ),
    ):
        await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    await snapshot_platform(hass, entity_registry, snapshot, mock_config_entry.entry_id)


async def test_invalid_path(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, tmp_path: Path
) -> None:
    """Test that an invalid path is caught."""
    test_file = str(tmp_path.joinpath(TEST_FILE_NAME))
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry, unique_id=test_file, data={CONF_FILE_PATH: test_file}
    )

    state = hass.states.get("sensor." + TEST_FILE_NAME)
    assert not state


async def test_valid_path(
    hass: HomeAssistant,
    tmp_path: Path,
    mock_config_entry: MockConfigEntry,
    device_registry: dr.DeviceRegistry,
) -> None:
    """Test for a valid path."""
    testfile = str(tmp_path.joinpath("file.txt"))
    await async_create_file(hass, testfile)
    hass.config.allowlist_external_dirs = {tmp_path}
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry, unique_id=testfile, data={CONF_FILE_PATH: testfile}
    )

    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    state = hass.states.get("sensor.mock_file_test_filesize_txt_size")
    assert state
    assert state.state == "0.0"

    device = device_registry.async_get_device(
        identifiers={(DOMAIN, mock_config_entry.entry_id)}
    )
    assert device.name == mock_config_entry.title

    await hass.async_add_executor_job(os.remove, testfile)


async def test_state_unavailable(
    hass: HomeAssistant, tmp_path: Path, mock_config_entry: MockConfigEntry
) -> None:
    """Verify we handle state unavailable."""
    testfile = str(tmp_path.joinpath("file.txt"))
    await async_create_file(hass, testfile)
    hass.config.allowlist_external_dirs = {tmp_path}
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry, unique_id=testfile, data={CONF_FILE_PATH: testfile}
    )

    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    state = hass.states.get("sensor.mock_file_test_filesize_txt_size")
    assert state
    assert state.state == "0.0"

    await hass.async_add_executor_job(os.remove, testfile)
    await async_update_entity(hass, "sensor.mock_file_test_filesize_txt_size")

    state = hass.states.get("sensor.mock_file_test_filesize_txt_size")
    assert state.state == STATE_UNAVAILABLE
