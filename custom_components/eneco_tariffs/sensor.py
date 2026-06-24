from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import EnecoCoordinator


@dataclass(frozen=True, kw_only=True)
class EnecoSensorEntityDescription(SensorEntityDescription):
    data_key: str
    extra_attrs_key: str | None = None
    rating_key: str | None = None


SENSORS: tuple[EnecoSensorEntityDescription, ...] = (
    EnecoSensorEntityDescription(
        key="electricity_current_price",
        data_key="electricity_current_price",
        name="Electricity Price (current hour)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:lightning-bolt",
        extra_attrs_key="electricity_prices_today",
        rating_key="electricity_current_rating",
    ),
    EnecoSensorEntityDescription(
        key="electricity_next_price",
        data_key="electricity_next_price",
        name="Electricity Price (next hour)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:lightning-bolt-outline",
        rating_key="electricity_next_rating",
    ),
    EnecoSensorEntityDescription(
        key="electricity_rate",
        data_key="electricity_rate",
        name="Electricity Rate (from tariff)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:currency-eur",
        entity_registry_enabled_default=False,
    ),
    EnecoSensorEntityDescription(
        key="gas_current_price",
        data_key="gas_current_price",
        name="Gas Price",
        native_unit_of_measurement="EUR/m³",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:gas-burner",
    ),
    EnecoSensorEntityDescription(
        key="electricity_average_price",
        data_key="electricity_average_price",
        name="Electricity Average Price (today)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:lightning-bolt",
    ),
    EnecoSensorEntityDescription(
        key="electricity_current_market_price",
        data_key="electricity_current_market_price",
        name="Electricity Market Price (current hour)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:chart-line",
    ),
    EnecoSensorEntityDescription(
        key="electricity_next_market_price",
        data_key="electricity_next_market_price",
        name="Electricity Market Price (next hour)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:chart-line-variant",
    ),
    EnecoSensorEntityDescription(
        key="electricity_highest_price",
        data_key="electricity_highest_price",
        name="Electricity Highest Price (today)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:arrow-up-bold",
    ),
    EnecoSensorEntityDescription(
        key="electricity_lowest_price",
        data_key="electricity_lowest_price",
        name="Electricity Lowest Price (today)",
        native_unit_of_measurement="EUR/kWh",
        device_class=SensorDeviceClass.MONETARY,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:arrow-down-bold",
    ),
    EnecoSensorEntityDescription(
        key="electricity_current_pct_of_range",
        data_key="electricity_current_pct_of_range",
        name="Electricity Price Position in Range",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:percent",
    ),
    EnecoSensorEntityDescription(
        key="electricity_current_pct_of_highest",
        data_key="electricity_current_pct_of_highest",
        name="Electricity Price Percentage of Highest",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:percent",
    ),
    EnecoSensorEntityDescription(
        key="electricity_highest_price_time",
        data_key="electricity_highest_price_time",
        name="Time of Highest Electricity Price",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-alert",
    ),
    EnecoSensorEntityDescription(
        key="electricity_lowest_price_time",
        data_key="electricity_lowest_price_time",
        name="Time of Lowest Electricity Price",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-check",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EnecoCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        EnecoSensor(coordinator, description, entry)
        for description in SENSORS
    )


class EnecoSensor(CoordinatorEntity[EnecoCoordinator], SensorEntity):
    """A sensor for a single Eneco tariff data point."""

    entity_description: EnecoSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EnecoCoordinator,
        description: EnecoSensorEntityDescription,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="Eneco Dynamic Tariffs",
            manufacturer="Eneco",
            model="Dynamic Energy Contract",
            configuration_url="https://www.eneco.nl/mijn-eneco/",
        )

    @property
    def native_value(self) -> float | datetime | None:
        if self.coordinator.data is None:
            return None
        value = self.coordinator.data.get(self.entity_description.data_key)
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        try:
            return round(float(value), 5)
        except (TypeError, ValueError):
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if self.coordinator.data is None:
            return None
        attrs: dict[str, Any] = {}
        if self.entity_description.extra_attrs_key:
            prices = self.coordinator.data.get(self.entity_description.extra_attrs_key)
            if prices:
                attrs["prices"] = prices
        if self.entity_description.rating_key:
            rating = self.coordinator.data.get(self.entity_description.rating_key)
            if rating:
                attrs["rating"] = rating
        if self.entity_description.key == "electricity_current_price":
            prices_tomorrow = self.coordinator.data.get("electricity_prices_tomorrow")
            if prices_tomorrow:
                attrs["prices_tomorrow"] = prices_tomorrow
        return attrs or None
