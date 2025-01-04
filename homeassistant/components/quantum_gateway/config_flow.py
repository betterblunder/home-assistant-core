"""Config flow for Quantum Gateway integration."""

from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_BASE, CONF_HOST, CONF_PASSWORD
import homeassistant.helpers.config_validation as cv

from .const import DEFAULT_HOST, DOMAIN
from .lib import QuantumGatewayScanner


class QuantumGatewayFlowHandler(ConfigFlow, domain=DOMAIN):
    """Example config flow."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the Quantum Gateway config flow."""
        super().__init__()
        self._config_data: dict[str, Any] = {}
        self.quantum: QuantumGatewayScanner

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow start."""

        schema = vol.Schema(
            {
                vol.Optional(CONF_HOST, default=DEFAULT_HOST): cv.string,
                vol.Required(CONF_PASSWORD): str,
            }
        )

        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=schema)

        self._config_data = user_input
        self.quantum = QuantumGatewayScanner(
            user_input[CONF_HOST], user_input[CONF_PASSWORD]
        )
        success_init = await self.quantum.success_init

        if not success_init:
            return self.async_show_form(
                step_id="user", data_schema=schema, errors={CONF_BASE: "cannot connect"}
            )
        return self.async_create_entry(title=user_input[CONF_HOST], data=user_input)
