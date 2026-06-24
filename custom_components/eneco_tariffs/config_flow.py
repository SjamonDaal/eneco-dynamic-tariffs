from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN
from .coordinator import EnecoApiClient, EnecoAuthError

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


class EnecoConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Eneco Dynamic Tariffs config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            client = EnecoApiClient()
            try:
                await client.authenticate(username, password)
            except EnecoAuthError as err:
                _LOGGER.warning("Eneco authentication failed during setup: %s", err)
                errors["base"] = "invalid_auth"
            except Exception:
                _LOGGER.exception("Unexpected error during Eneco authentication")
                errors["base"] = "cannot_connect"
            else:
                return self.async_create_entry(
                    title=f"Eneco ({username})",
                    data={
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    },
                )
            finally:
                await client.close()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
