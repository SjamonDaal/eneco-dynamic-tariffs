from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
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
    DYNAMIC_PRICES_URL,
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
            if name == "credentials":
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
                elif name == "credentials":
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
            # aiohttp CookieJar yields Morsel objects: name is .key,
            # domain/path are accessed as dict items, not attributes
            cookies.append(
                {
                    "name": cookie.key,
                    "value": cookie.value,
                    "domain": cookie.get("domain") or "",
                    "path": cookie.get("path") or "/",
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

    async def get_dynamic_prices(self, date: str) -> dict[str, Any]:
        """Fetch all-in hourly prices (incl. VAT) for the given local date."""
        session = await self._get_session()
        params = {"start": date, "interval": "Hour", "aggregation": "Day"}
        async with session.get(
            DYNAMIC_PRICES_URL, params=params, headers=self._api_headers
        ) as resp:
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
            _LOGGER.debug("Eneco products fetched")
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco products: %s", err)

        try:
            raw["prices_today"] = await self._client.get_dynamic_prices(today)
            _LOGGER.debug("Eneco dynamic prices (today) fetched")
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco dynamic prices (today): %s", err)

        try:
            raw["prices_tomorrow"] = await self._client.get_dynamic_prices(tomorrow)
            _LOGGER.debug("Eneco dynamic prices (tomorrow) fetched")
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.debug("No Eneco dynamic prices for tomorrow yet: %s", err)

        return _parse_tariff_data(raw)

    async def async_shutdown(self) -> None:
        await self._client.close()
        await super().async_shutdown()


# ------------------------------------------------------------------
# Data parsing helpers
# ------------------------------------------------------------------


def _parse_tariff_data(raw: dict[str, Any]) -> dict[str, Any]:
    now_utc = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    next_utc = now_utc + timedelta(hours=1)

    prices_today = _extract_dynamic_prices(raw.get("prices_today", {}), "electricity")
    prices_tomorrow = _extract_dynamic_prices(raw.get("prices_tomorrow", {}), "electricity")
    all_prices = prices_today + prices_tomorrow

    current_entry = _price_entry_at(all_prices, now_utc)
    next_entry = _price_entry_at(all_prices, next_utc)

    # Gas changes daily — grab the first slice's price
    gas_slices = _extract_dynamic_prices(raw.get("prices_today", {}), "gas")
    gas_price = gas_slices[0]["price"] if gas_slices else _extract_gas_price(raw.get("products", {}))

    return {
        "electricity_current_price": current_entry["price"] if current_entry else None,
        "electricity_current_rating": current_entry.get("rating") if current_entry else None,
        "electricity_next_price": next_entry["price"] if next_entry else None,
        "electricity_next_rating": next_entry.get("rating") if next_entry else None,
        "electricity_rate": _extract_electricity_price(raw.get("products", {})),
        "gas_current_price": gas_price,
        "electricity_prices_today": prices_today,
        "electricity_prices_tomorrow": prices_tomorrow,
    }


def _extract_dynamic_prices(
    data: dict[str, Any], product_type: str = "electricity"
) -> list[dict[str, Any]]:
    """Parse slices from the /dxpweb/public/nl/eneco/dynamic/prices endpoint.

    Structure: data.products[{productType}].slices[].{start, price.total, price.rating}
    Timestamps are UTC (trailing 'Z').
    """
    for product in data.get("data", {}).get("products", []):
        if product.get("productType") != product_type:
            continue
        entries = []
        for slice_ in product.get("slices", []):
            ts = slice_.get("start")
            price_obj = slice_.get("price", {})
            price = _to_float(price_obj.get("total"))
            rating = price_obj.get("rating", "average")
            if ts and price is not None:
                entries.append({"start": ts, "price": round(price, 7), "rating": rating})
        return entries
    return []


def _price_entry_at(
    prices: list[dict[str, Any]], dt_utc: datetime
) -> dict[str, Any] | None:
    """Return the price entry whose UTC hour matches dt_utc."""
    for entry in prices:
        ts = entry.get("start", "")
        try:
            entry_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if entry_dt == dt_utc:
                return entry
        except ValueError:
            continue
    return None


def _iter_products(products: dict[str, Any]):
    # Actual structure: {"data": {"products": [...]}}
    data = products.get("data")
    if isinstance(data, dict):
        prods = data.get("products")
        if isinstance(prods, list):
            return prods
    # Fallback for other possible structures
    for key in ("products", "items"):
        candidate = products.get(key)
        if isinstance(candidate, list):
            return candidate
    return products if isinstance(products, list) else []


def _product_type_name(product: dict[str, Any]) -> str:
    """Return the normalised type name for a product dict."""
    type_field = product.get("type", {})
    if isinstance(type_field, dict):
        return type_field.get("name", "").lower()
    return str(type_field).lower()


def _find_rate(product: dict[str, Any]) -> float | None:
    # Actual structure: unitRates[].vatIncluded
    unit_rates = product.get("unitRates", [])
    if isinstance(unit_rates, list):
        for rate in unit_rates:
            if isinstance(rate, dict):
                val = _to_float(rate.get("vatIncluded"))
                if val is not None:
                    return val
    return None


def _extract_gas_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        if not isinstance(product, dict):
            continue
        if _product_type_name(product) == "gas":
            return _find_rate(product)
    return None


def _extract_electricity_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        if not isinstance(product, dict):
            continue
        if _product_type_name(product) == "electricity":
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
