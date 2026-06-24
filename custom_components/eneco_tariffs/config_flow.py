from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import CONF_SESSION_COOKIES, DOMAIN
from .coordinator import EnecoApiClient, EnecoAuthError, EnecoTotpRequired

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_TOTP_SCHEMA = vol.Schema(
    {
        vol.Required("totp_code"): str,
    }
)


class EnecoConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Eneco Dynamic Tariffs config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._client: EnecoApiClient | None = None
        self._username: str = ""
        self._password: str = ""
        self._reauth_entry: ConfigEntry | None = None

    async def async_step_reauth(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle re-authentication when the stored session expires."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        if self._reauth_entry:
            self._username = self._reauth_entry.data.get(CONF_USERNAME, "")
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            password = user_input[CONF_PASSWORD]
            self._client = EnecoApiClient()
            self._password = password

            try:
                await self._client.authenticate(self._username, password)
            except EnecoTotpRequired:
                return await self.async_step_totp()
            except EnecoAuthError as err:
                _LOGGER.warning("Eneco re-authentication failed: %s", err)
                errors["base"] = "invalid_auth"
                await self._client.close()
                self._client = None
            except Exception:
                _LOGGER.exception("Unexpected error during Eneco re-authentication")
                errors["base"] = "cannot_connect"
                if self._client:
                    await self._client.close()
                    self._client = None
            else:
                return await self._create_entry()

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            description_placeholders={"username": self._username},
            errors=errors,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(username.lower())
            self._abort_if_unique_id_configured()

            self._client = EnecoApiClient()
            self._username = username
            self._password = password

            try:
                await self._client.authenticate(username, password)
            except EnecoTotpRequired:
                # Okta sent an email code — ask the user for it
                return await self.async_step_totp()
            except EnecoAuthError as err:
                _LOGGER.warning("Eneco authentication failed: %s", err)
                errors["base"] = "invalid_auth"
                await self._client.close()
                self._client = None
            except Exception:
                _LOGGER.exception("Unexpected error during Eneco authentication")
                errors["base"] = "cannot_connect"
                if self._client:
                    await self._client.close()
                    self._client = None
            else:
                return await self._create_entry()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )

    async def async_step_totp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask the user for the one-time code that Eneco sent by email."""
        errors: dict[str, str] = {}

        if user_input is not None:
            code = user_input["totp_code"].strip()
            try:
                await self._client.complete_totp(code)  # type: ignore[union-attr]
            except EnecoAuthError as err:
                _LOGGER.warning("Eneco TOTP verification failed: %s", err)
                errors["base"] = "invalid_totp"
            except Exception:
                _LOGGER.exception("Unexpected error during Eneco TOTP verification")
                errors["base"] = "cannot_connect"
            else:
                return await self._create_entry()

        return self.async_show_form(
            step_id="totp",
            data_schema=STEP_TOTP_SCHEMA,
            errors=errors,
            description_placeholders={"email": self._username},
        )

    async def _create_entry(self) -> ConfigFlowResult:
        cookies = self._client.get_session_cookies() if self._client else []  # type: ignore[union-attr]
        data = {
            CONF_USERNAME: self._username,
            CONF_PASSWORD: self._password,
            CONF_SESSION_COOKIES: cookies,
        }
        if self._reauth_entry:
            return self.async_update_reload_and_abort(self._reauth_entry, data=data)
        return self.async_create_entry(
            title=f"Eneco ({self._username})",
            data=data,
        )
