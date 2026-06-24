from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from yarl import URL
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    API_BASE,
    API_KEY,
    CONF_SESSION_COOKIES,
    DOMAIN,
    ENECO_WEB_BASE,
    OKTA_BASE,
    UPDATE_INTERVAL_MINUTES,
)

_LOGGER = logging.getLogger(__name__)


class EnecoAuthError(Exception):
    """Raised when Eneco authentication fails."""


class EnecoTotpRequired(Exception):
    """Raised when Okta requires an email TOTP code to continue."""


class EnecoApiClient:
    """Low-level Eneco API client."""

    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None
        self._token: str | None = None
        self._customer_id: str | None = None
        self._account_id: str | None = None
        self._pending_totp_state: dict[str, Any] | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar())
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    @property
    def _api_headers(self) -> dict[str, str]:
        headers = {"apikey": API_KEY}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self, username: str, password: str) -> None:
        """Start Okta authentication.

        Raises EnecoTotpRequired when Eneco asks for an email TOTP code.
        The caller must then invoke complete_totp() with the received code.
        """
        session = await self._get_session()

        async with session.get(f"{ENECO_WEB_BASE}/mijn-eneco/") as resp:
            await resp.read()

        async with session.get(f"{ENECO_WEB_BASE}/api/auth/csrf/") as resp:
            csrf_data = await resp.json(content_type=None)
        csrf_token = csrf_data.get("csrfToken")
        if not csrf_token:
            raise EnecoAuthError("Could not obtain CSRF token from Eneco")

        async with session.post(
            f"{ENECO_WEB_BASE}/api/auth/signin/okta/",
            data={
                "json": "true",
                "csrfToken": csrf_token,
                "callbackUrl": "/mijn-eneco/",
            },
        ) as resp:
            okta_init = await resp.json(content_type=None)
        okta_url = okta_init.get("url")
        if not okta_url:
            raise EnecoAuthError("No Okta redirect URL received from NextAuth")

        async with session.get(okta_url) as resp:
            okta_html = await resp.text()

        m = re.search(r'"stateToken"\s*:\s*"(.*?)"', okta_html)
        if not m:
            raise EnecoAuthError("Okta stateToken not found in login page HTML")
        # Okta embeds the token as a JSON string — decode escape sequences
        state_token = _unescape_okta_string(m.group(1))

        state = await self._post_json(
            session,
            f"{OKTA_BASE}/idp/idx/introspect",
            {"stateToken": state_token},
        )

        # May raise EnecoTotpRequired — caller handles it
        state = await self._run_auth_loop(session, state, username, password)
        await self._finalise_auth(session, state)

    async def complete_totp(self, code: str) -> None:
        """Submit the email TOTP code to finish a paused authentication."""
        if self._pending_totp_state is None:
            raise EnecoAuthError("No pending TOTP challenge — call authenticate() first")

        session = await self._get_session()
        state = self._pending_totp_state

        remediations = state.get("remediation", {}).get("value", [])
        if not remediations:
            raise EnecoAuthError("Pending TOTP state has no remediation form")

        form = remediations[0]
        href = form.get("href")
        if not href:
            raise EnecoAuthError("TOTP remediation form has no action URL")

        post: dict[str, Any] = {}
        for field in form.get("value", []):
            name = field.get("name", "")
            is_secret = field.get("secret", False)
            if name == "credentials" and is_secret:
                post[name] = {"passcode": code}
            elif "value" in field and not is_secret:
                post[name] = field["value"]

        _LOGGER.debug("Submitting TOTP code to %s", href)
        state = await self._post_json(session, href, post)

        # There should be no more remediations after a correct TOTP code
        if "success" not in state:
            # One more loop iteration in case Okta adds a step
            state = await self._run_auth_loop(session, state, "", "")

        self._pending_totp_state = None
        await self._finalise_auth(session, state)

    async def _run_auth_loop(
        self,
        session: aiohttp.ClientSession,
        initial_state: dict[str, Any],
        username: str,
        password: str,
    ) -> dict[str, Any]:
        """Walk through Okta IDX remediation steps; detect TOTP challenge."""
        state = initial_state
        password_submitted = False

        for i in range(15):
            remediation_names = [
                r.get("name") for r in state.get("remediation", {}).get("value", [])
            ]
            _LOGGER.warning(
                "Eneco IDX step %d — top-level keys: %s | remediations: %s",
                i,
                list(state.keys()),
                remediation_names,
            )
            # Log field names inside each form (without values, to avoid leaking secrets)
            for rem in state.get("remediation", {}).get("value", []):
                field_names = [f.get("name") for f in rem.get("value", [])]
                _LOGGER.warning(
                    "  form '%s' href=%s fields=%s",
                    rem.get("name"),
                    rem.get("href"),
                    field_names,
                )

            if "success" in state:
                return state

            for msg in state.get("messages", {}).get("value", []):
                _LOGGER.warning("Okta message: %s", msg.get("message", msg))

            remediations = state.get("remediation", {}).get("value", [])
            if not remediations:
                msgs = state.get("messages", {}).get("value", [])
                detail = msgs[0].get("message", "unknown") if msgs else "no remediations"
                raise EnecoAuthError(f"Okta authentication blocked: {detail}")

            form = remediations[0]
            form_name = form.get("name", "")
            href = form.get("href")

            if not href:
                raise EnecoAuthError(f"Okta form '{form_name}' has no action URL")

            post: dict[str, Any] = {}
            totp_needed = False

            for field in form.get("value", []):
                name = field.get("name", "")
                is_secret = field.get("secret", False)

                if name == "identifier":
                    post[name] = username
                elif name == "credentials" and is_secret:
                    if password_submitted:
                        # A second credentials challenge after password = email TOTP
                        _LOGGER.warning("Eneco IDX — email TOTP challenge detected at step %d", i)
                        totp_needed = True
                        break
                    post[name] = {"passcode": password}
                    password_submitted = True
                elif name == "authenticator":
                    options = field.get("options", [])
                    chosen = next(
                        (
                            opt["value"]
                            for opt in options
                            if isinstance(opt.get("value"), dict)
                            and opt["value"].get("methodType") == "password"
                        ),
                        options[0]["value"] if options else None,
                    )
                    if chosen is not None:
                        post[name] = chosen
                elif "value" in field and not is_secret:
                    post[name] = field["value"]

            if totp_needed:
                self._pending_totp_state = state
                raise EnecoTotpRequired()

            _LOGGER.warning(
                "Eneco IDX step %d — posting to %s with keys: %s",
                i,
                href,
                list(post.keys()),
            )
            state = await self._post_json(session, href, post)

        raise EnecoAuthError(
            f"Okta IDX loop exceeded maximum iterations. "
            f"Last state keys: {list(state.keys())} | "
            f"Last remediations: {[r.get('name') for r in state.get('remediation', {}).get('value', [])]}"
        )

    async def _finalise_auth(
        self, session: aiohttp.ClientSession, state: dict[str, Any]
    ) -> None:
        """Follow the success URL and extract the ID token + account IDs."""
        success_href = state.get("success", {}).get("href")
        if not success_href:
            raise EnecoAuthError("Okta success state has no href")

        async with session.get(success_href) as resp:
            success_html = await resp.text()

        _LOGGER.debug("Post-auth page length: %d chars", len(success_html))

        if m := re.search(r'"idToken"\s*:\s*"(.*?)"', success_html):
            self._token = m.group(1)
        if m := re.search(r'"customerId"\s*:\s*(\d+)', success_html):
            self._customer_id = m.group(1)
        if m := re.search(r'"accountId"\s*:\s*(\d+)', success_html):
            self._account_id = m.group(1)

        if not self._token:
            raise EnecoAuthError("idToken not found in post-authentication page")
        if not self._customer_id or not self._account_id:
            raise EnecoAuthError("Customer/account IDs not found in post-authentication page")

        _LOGGER.debug(
            "Authenticated — customer=%s account=%s",
            self._customer_id,
            self._account_id,
        )

    # ------------------------------------------------------------------
    # Session-cookie persistence (avoids repeated TOTP on restart)
    # ------------------------------------------------------------------

    def get_session_cookies(self) -> list[dict[str, str]]:
        """Return current session cookies as a JSON-serialisable list."""
        if not self._session or self._session.closed:
            return []
        cookies = []
        for cookie in self._session.cookie_jar:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain or "",
                    "path": cookie.path or "/",
                }
            )
        return cookies

    async def restore_session_cookies(self, cookies: list[dict[str, str]]) -> None:
        """Load stored cookies into the session jar."""
        session = await self._get_session()
        for c in cookies:
            domain = c.get("domain", "").lstrip(".")
            if domain:
                url = URL(f"https://{domain}/")
                session.cookie_jar.update_cookies({c["name"]: c["value"]}, url)

    async def refresh_token_from_session(self) -> bool:
        """Obtain a fresh idToken from the NextAuth session endpoint.

        Returns True if the stored session is still valid and credentials were
        successfully refreshed without requiring TOTP.
        """
        session = await self._get_session()
        try:
            async with session.get(f"{ENECO_WEB_BASE}/api/auth/session") as resp:
                if resp.status != 200:
                    _LOGGER.debug("Session endpoint returned %d", resp.status)
                    return False
                data = await resp.json(content_type=None)

            _LOGGER.debug("NextAuth session response: %s", data)

            id_token = (
                data.get("idToken")
                or data.get("accessToken")
                or data.get("user", {}).get("idToken")
            )
            if not id_token:
                return False

            self._token = id_token

            data_str = str(data)
            if m := re.search(r'"customerId"\s*:\s*(\d+)', data_str):
                self._customer_id = m.group(1)
            if m := re.search(r'"accountId"\s*:\s*(\d+)', data_str):
                self._account_id = m.group(1)

            return bool(self._token and self._customer_id and self._account_id)

        except Exception as err:
            _LOGGER.debug("Session refresh failed: %s", err)
            return False

    # ------------------------------------------------------------------
    # Data endpoints
    # ------------------------------------------------------------------

    async def get_products(self) -> dict[str, Any]:
        session = await self._get_session()
        url = (
            f"{API_BASE}/dxpweb/v2/nl/eneco/customers/{self._customer_id}"
            f"/accounts/{self._account_id}/products?includeproductrates=true"
        )
        async with session.get(url, headers=self._api_headers) as resp:
            if resp.status == 401:
                raise EnecoAuthError("API token rejected (401)")
            resp.raise_for_status()
            return await resp.json(content_type=None)

    async def get_usages(
        self, start: str, aggregation: str = "Day", interval: str = "Hour"
    ) -> dict[str, Any]:
        session = await self._get_session()
        params = {
            "aggregation": aggregation,
            "interval": interval,
            "start": start,
            "addBudget": "true",
            "addWeather": "false",
            "extrapolate": "false",
        }
        url = (
            f"{API_BASE}/dxpweb/nl/eneco/customers/{self._customer_id}"
            f"/accounts/{self._account_id}/usages"
        )
        async with session.get(url, params=params, headers=self._api_headers) as resp:
            if resp.status == 401:
                raise EnecoAuthError("API token rejected (401)")
            resp.raise_for_status()
            return await resp.json(content_type=None)

    async def get_insights(self) -> dict[str, Any]:
        session = await self._get_session()
        url = (
            f"{API_BASE}/dxpweb/v2/nl/eneco/customers/{self._customer_id}"
            f"/accounts/{self._account_id}/usages/services/insights"
        )
        async with session.get(url, headers=self._api_headers) as resp:
            if resp.status == 401:
                raise EnecoAuthError("API token rejected (401)")
            resp.raise_for_status()
            return await resp.json(content_type=None)

    @staticmethod
    async def _post_json(
        session: aiohttp.ClientSession,
        url: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        async with session.post(
            url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        ) as resp:
            return await resp.json(content_type=None)


# ------------------------------------------------------------------
# Coordinator
# ------------------------------------------------------------------


class EnecoCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Manages periodic Eneco tariff data updates."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=UPDATE_INTERVAL_MINUTES),
        )
        self.entry = entry
        self._client = EnecoApiClient()
        self._authenticated = False

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            if not self._authenticated:
                await self._authenticate()
            return await self._fetch_data()

        except EnecoAuthError as err:
            self._authenticated = False
            _LOGGER.debug("Auth error, retrying: %s", err)
            try:
                await self._authenticate()
                return await self._fetch_data()
            except (EnecoAuthError, EnecoTotpRequired) as retry_err:
                raise ConfigEntryAuthFailed(str(retry_err)) from retry_err

        except ConfigEntryAuthFailed:
            raise

        except Exception as err:
            raise UpdateFailed(f"Error communicating with Eneco: {err}") from err

    async def _authenticate(self) -> None:
        """Authenticate, preferring stored session cookies over full re-auth."""
        stored_cookies: list[dict] = self.entry.data.get(CONF_SESSION_COOKIES, [])

        if stored_cookies:
            await self._client.restore_session_cookies(stored_cookies)
            if await self._client.refresh_token_from_session():
                _LOGGER.debug("Eneco session restored from stored cookies")
                self._authenticated = True
                return
            _LOGGER.debug("Stored session expired, falling back to full auth")

        # Full auth — will raise ConfigEntryAuthFailed if TOTP is needed
        # (TOTP must be handled via the config flow, not here)
        try:
            await self._client.authenticate(
                self.entry.data[CONF_USERNAME],
                self.entry.data[CONF_PASSWORD],
            )
        except EnecoTotpRequired as err:
            raise ConfigEntryAuthFailed(
                "Eneco requires email verification. Please re-configure the integration."
            ) from err

        self._authenticated = True
        await self._save_cookies()

    async def _save_cookies(self) -> None:
        cookies = self._client.get_session_cookies()
        if cookies:
            self.hass.config_entries.async_update_entry(
                self.entry,
                data={**self.entry.data, CONF_SESSION_COOKIES: cookies},
            )

    async def _fetch_data(self) -> dict[str, Any]:
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        raw: dict[str, Any] = {}

        try:
            raw["products"] = await self._client.get_products()
            _LOGGER.debug("Eneco products: %s", raw["products"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco products: %s", err)

        try:
            raw["usages_today"] = await self._client.get_usages(today)
            _LOGGER.debug("Eneco usages today: %s", raw["usages_today"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco usages (today): %s", err)

        try:
            raw["usages_tomorrow"] = await self._client.get_usages(tomorrow)
            _LOGGER.debug("Eneco usages tomorrow: %s", raw["usages_tomorrow"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.debug("No Eneco usage data for tomorrow yet: %s", err)

        try:
            raw["insights"] = await self._client.get_insights()
            _LOGGER.debug("Eneco insights: %s", raw["insights"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco insights: %s", err)

        return _parse_tariff_data(raw)

    async def async_shutdown(self) -> None:
        await self._client.close()
        await super().async_shutdown()


# ------------------------------------------------------------------
# Data parsing helpers
# ------------------------------------------------------------------


def _parse_tariff_data(raw: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now().astimezone()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    next_hour = current_hour + timedelta(hours=1)

    prices_today = _extract_hourly_prices(raw.get("usages_today", {}))
    prices_tomorrow = _extract_hourly_prices(raw.get("usages_tomorrow", {}))

    return {
        "electricity_current_price": _price_at(prices_today, current_hour.isoformat()),
        "electricity_next_price": (
            _price_at(prices_today, next_hour.isoformat())
            or _price_at(prices_tomorrow, next_hour.isoformat())
        ),
        "electricity_rate": _extract_electricity_price(raw.get("products", {})),
        "gas_current_price": _extract_gas_price(raw.get("products", {})),
        "electricity_prices_today": prices_today,
        "electricity_prices_tomorrow": prices_tomorrow,
        "raw": raw,
    }


def _extract_hourly_prices(usages: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[Any] = []
    for key in ("data", "usages", "measurements", "values", "items"):
        candidate = usages.get(key)
        if isinstance(candidate, list):
            rows = candidate
            break
    if not rows and isinstance(usages, list):
        rows = usages

    entries = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ts = row.get("dateTime") or row.get("start") or row.get("timestamp")
        if not ts:
            continue
        usage = _to_float(row.get("totalUsage") or row.get("usage") or row.get("quantity"))
        cost = _to_float(
            row.get("totalUsageCostInclVat")
            or row.get("totalCostInclVat")
            or row.get("costInclVat")
        )
        if usage and cost and usage > 0:
            entries.append({"start": ts, "price": round(cost / usage, 5)})
        elif _to_float(row.get("priceInclVat")) is not None:
            entries.append({"start": ts, "price": round(row["priceInclVat"], 5)})
    return entries


def _price_at(prices: list[dict[str, Any]], iso_ts: str) -> float | None:
    for entry in prices:
        if entry.get("start", "").startswith(iso_ts[:16]):
            return entry["price"]
    return None


def _iter_products(products: dict[str, Any]):
    for key in ("products", "data", "items"):
        candidate = products.get(key)
        if isinstance(candidate, list):
            return candidate
    return products if isinstance(products, list) else []


def _find_rate(product: dict[str, Any]) -> float | None:
    for rates_key in ("rates", "productRates", "tariff"):
        rates = product.get(rates_key)
        if isinstance(rates, dict):
            for price_key in ("priceInclVat", "price", "usagePriceInclVat", "variableRate"):
                val = _to_float(rates.get(price_key))
                if val is not None:
                    return val
        elif isinstance(rates, list):
            for rate in rates:
                if isinstance(rate, dict):
                    for price_key in ("priceInclVat", "price", "usagePriceInclVat"):
                        val = _to_float(rate.get(price_key))
                        if val is not None:
                            return val
    return None


def _extract_gas_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        if not isinstance(product, dict):
            continue
        commodity = (product.get("commodity") or product.get("type") or "").lower()
        if "gas" in commodity:
            return _find_rate(product)
    return None


def _extract_electricity_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        if not isinstance(product, dict):
            continue
        commodity = (product.get("commodity") or product.get("type") or "").lower()
        if "electricity" in commodity or "stroom" in commodity or "elektr" in commodity:
            return _find_rate(product)
    return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _unescape_okta_string(s: str) -> str:
    """Decode escape sequences Okta embeds in HTML-inlined JSON (e.g. \\x2D → -)."""
    # Simple hex escape replacement; avoids full unicode_escape codec pitfalls
    import re as _re
    return _re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
