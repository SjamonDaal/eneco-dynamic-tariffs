from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Any

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import API_BASE, API_KEY, DOMAIN, ENECO_WEB_BASE, OKTA_BASE, UPDATE_INTERVAL_MINUTES

_LOGGER = logging.getLogger(__name__)


class EnecoAuthError(Exception):
    """Raised when Eneco authentication fails."""


class EnecoApiClient:
    """Low-level Eneco API client."""

    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None
        self._token: str | None = None
        self._customer_id: str | None = None
        self._account_id: str | None = None

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

    async def authenticate(self, username: str, password: str) -> None:
        """Authenticate against Eneco via NextAuth + Okta IDX flow."""
        session = await self._get_session()

        # Load the protected page to seed cookies
        async with session.get(f"{ENECO_WEB_BASE}/mijn-eneco/") as resp:
            await resp.read()

        # Obtain NextAuth CSRF token
        async with session.get(f"{ENECO_WEB_BASE}/api/auth/csrf/") as resp:
            csrf_data = await resp.json(content_type=None)
        csrf_token = csrf_data.get("csrfToken")
        if not csrf_token:
            raise EnecoAuthError("Could not obtain CSRF token from Eneco")

        # Tell NextAuth to sign in via Okta; receive the Okta redirect URL
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

        # Load the Okta login page and extract the stateToken embedded in the HTML
        async with session.get(okta_url) as resp:
            okta_html = await resp.text()
        m = re.search(r'"stateToken"\s*:\s*"(.*?)"', okta_html)
        if not m:
            raise EnecoAuthError("Okta stateToken not found in login page HTML")
        # Unescape unicode escape sequences Okta embeds (e.g. \x2D → -)
        state_token = m.group(1).encode("utf-8").decode("unicode_escape")

        # Begin the Okta IDX remediation loop
        state = await self._post_json(
            session,
            f"{OKTA_BASE}/idp/idx/introspect",
            {"stateToken": state_token},
        )
        state = await self._run_auth_loop(session, state, username, password)

        # Follow the success URL to pick up the ID token and account identifiers
        success_href = state.get("success", {}).get("href")
        if not success_href:
            raise EnecoAuthError("Okta authentication succeeded but no success URL was returned")

        async with session.get(success_href) as resp:
            success_html = await resp.text()

        if m := re.search(r'"idToken"\s*:\s*"(.*?)"', success_html):
            self._token = m.group(1)
        if m := re.search(r'"customerId"\s*:\s*(\d+)', success_html):
            self._customer_id = m.group(1)
        if m := re.search(r'"accountId"\s*:\s*(\d+)', success_html):
            self._account_id = m.group(1)

        if not self._token:
            raise EnecoAuthError("ID token not found in post-authentication response")
        if not self._customer_id or not self._account_id:
            raise EnecoAuthError("Customer/account IDs not found in post-authentication response")

        _LOGGER.debug(
            "Eneco authentication successful (customer=%s, account=%s)",
            self._customer_id,
            self._account_id,
        )

    async def _run_auth_loop(
        self,
        session: aiohttp.ClientSession,
        state: dict[str, Any],
        username: str,
        password: str,
    ) -> dict[str, Any]:
        """Walk through the Okta IDX remediation steps until success or error."""
        for _ in range(10):
            if "success" in state:
                return state

            remediations = state.get("remediation", {}).get("value", [])
            if not remediations:
                messages = state.get("messages", {}).get("value", [])
                detail = messages[0].get("message", "unknown") if messages else "no remediations"
                raise EnecoAuthError(f"Okta authentication blocked: {detail}")

            form = remediations[0]
            href = form.get("href")
            if not href:
                raise EnecoAuthError("Okta remediation form has no action URL")

            post: dict[str, Any] = {}
            for field in form.get("value", []):
                name = field.get("name", "")
                is_secret = field.get("secret", False)

                if name == "identifier":
                    post[name] = username
                elif name == "credentials" and is_secret:
                    post[name] = {"passcode": password}
                elif name == "authenticator":
                    # Select the password authenticator when asked to choose
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

            state = await self._post_json(session, href, post)

        raise EnecoAuthError("Okta IDX loop exceeded maximum iterations")

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

    async def get_products(self) -> dict[str, Any]:
        """Retrieve account products including current tariff rates."""
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
        self,
        start: str,
        aggregation: str = "Day",
        interval: str = "Hour",
    ) -> dict[str, Any]:
        """Retrieve hourly usage data for a given start date (YYYY-MM-DD)."""
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
        """Retrieve usage insights for the account."""
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


class EnecoCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Manages periodic data updates for the Eneco integration."""

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
            _LOGGER.debug("Auth error during update, retrying once: %s", err)
            try:
                await self._authenticate()
                return await self._fetch_data()
            except EnecoAuthError as retry_err:
                raise ConfigEntryAuthFailed(str(retry_err)) from retry_err

        except ConfigEntryAuthFailed:
            raise

        except Exception as err:
            raise UpdateFailed(f"Error communicating with Eneco: {err}") from err

    async def _authenticate(self) -> None:
        await self._client.authenticate(
            self.entry.data[CONF_USERNAME],
            self.entry.data[CONF_PASSWORD],
        )
        self._authenticated = True

    async def _fetch_data(self) -> dict[str, Any]:
        today = datetime.now().strftime("%Y-%m-%d")
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")

        raw: dict[str, Any] = {}

        try:
            raw["products"] = await self._client.get_products()
            _LOGGER.debug("Eneco products response: %s", raw["products"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco products: %s", err)

        try:
            raw["usages_today"] = await self._client.get_usages(today)
            _LOGGER.debug("Eneco usages (today): %s", raw["usages_today"])
        except EnecoAuthError:
            raise
        except Exception as err:
            _LOGGER.warning("Failed to fetch Eneco usages for today: %s", err)

        try:
            raw["usages_tomorrow"] = await self._client.get_usages(tomorrow)
            _LOGGER.debug("Eneco usages (tomorrow): %s", raw["usages_tomorrow"])
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


def _parse_tariff_data(raw: dict[str, Any]) -> dict[str, Any]:
    """Transform raw API responses into a flat tariff data dict used by sensors."""
    now = datetime.now().astimezone()
    current_hour_str = now.replace(minute=0, second=0, microsecond=0).isoformat()
    next_hour_str = (now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)).isoformat()

    electricity_prices_today = _extract_hourly_prices(raw.get("usages_today", {}))
    electricity_prices_tomorrow = _extract_hourly_prices(raw.get("usages_tomorrow", {}))

    current_price = _price_at(electricity_prices_today, current_hour_str)
    next_price = _price_at(electricity_prices_today, next_hour_str) or _price_at(
        electricity_prices_tomorrow, next_hour_str
    )

    gas_price = _extract_gas_price(raw.get("products", {}))
    electricity_price_from_products = _extract_electricity_price(raw.get("products", {}))

    return {
        "electricity_current_price": current_price,
        "electricity_next_price": next_price,
        # Fallback to products rate when no hourly usage data exists
        "electricity_rate": electricity_price_from_products,
        "gas_current_price": gas_price,
        "electricity_prices_today": electricity_prices_today,
        "electricity_prices_tomorrow": electricity_prices_tomorrow,
        "raw": raw,
    }


def _extract_hourly_prices(usages: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract a list of {start, price} dicts from a usages API response.

    The exact response structure is determined at runtime; this function
    attempts common key patterns seen in Eneco's DXP API responses.
    """
    entries: list[dict[str, Any]] = []

    # Try top-level list keys
    rows: list[Any] = []
    for key in ("data", "usages", "measurements", "values", "items"):
        candidate = usages.get(key)
        if isinstance(candidate, list):
            rows = candidate
            break

    if not rows and isinstance(usages, list):
        rows = usages

    for row in rows:
        if not isinstance(row, dict):
            continue

        # Determine timestamp
        ts = row.get("dateTime") or row.get("start") or row.get("timestamp")
        if not ts:
            continue

        # Try to derive per-unit price from cost ÷ usage
        usage = _coerce_float(row.get("totalUsage") or row.get("usage") or row.get("quantity"))
        cost = _coerce_float(
            row.get("totalUsageCostInclVat")
            or row.get("totalCostInclVat")
            or row.get("costInclVat")
        )
        if usage and cost and usage > 0:
            entries.append({"start": ts, "price": round(cost / usage, 5)})
        elif _coerce_float(row.get("priceInclVat")) is not None:
            entries.append({"start": ts, "price": round(row["priceInclVat"], 5)})

    return entries


def _price_at(prices: list[dict[str, Any]], iso_ts: str) -> float | None:
    for entry in prices:
        if entry.get("start", "").startswith(iso_ts[:16]):
            return entry["price"]
    return None


def _extract_gas_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        commodity = (product.get("commodity") or product.get("type") or "").lower()
        if "gas" in commodity:
            return _find_rate(product)
    return None


def _extract_electricity_price(products: dict[str, Any]) -> float | None:
    for product in _iter_products(products):
        commodity = (product.get("commodity") or product.get("type") or "").lower()
        if "electricity" in commodity or "stroom" in commodity or "elektr" in commodity:
            return _find_rate(product)
    return None


def _iter_products(products: dict[str, Any]):
    for key in ("products", "data", "items"):
        candidate = products.get(key)
        if isinstance(candidate, list):
            return candidate
    if isinstance(products, list):
        return products
    return []


def _find_rate(product: dict[str, Any]) -> float | None:
    for rates_key in ("rates", "productRates", "tariff"):
        rates = product.get(rates_key)
        if isinstance(rates, dict):
            for price_key in ("priceInclVat", "price", "usagePriceInclVat", "variableRate"):
                val = _coerce_float(rates.get(price_key))
                if val is not None:
                    return val
        elif isinstance(rates, list):
            for rate in rates:
                if isinstance(rate, dict):
                    for price_key in ("priceInclVat", "price", "usagePriceInclVat"):
                        val = _coerce_float(rate.get(price_key))
                        if val is not None:
                            return val
    return None


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
