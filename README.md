# Eneco Dynamic Tariffs

A [HACS](https://hacs.xyz) integration for Home Assistant that fetches dynamic electricity and gas prices from [Eneco](https://www.eneco.nl).

## Requirements

- A Mijn Eneco account with a dynamic energy contract (Eneco Dynamisch)
- Home Assistant 2023.1 or newer
- HACS installed

## Installation

1. In HACS, go to **Integrations** → click the three-dot menu → **Custom repositories**
2. Add this repository URL and select category **Integration**
3. Install **Eneco Dynamic Tariffs** and restart Home Assistant
4. Go to **Settings → Devices & Services → Add Integration** and search for **Eneco Dynamic Tariffs**
5. Enter your Mijn Eneco email address and password

## Sensors

| Entity | Unit | Description |
|---|---|---|
| `sensor.electricity_price_current_hour` | EUR/kWh | Price for the current hour (incl. VAT) |
| `sensor.electricity_price_next_hour` | EUR/kWh | Price for the next hour (incl. VAT) |
| `sensor.gas_price` | EUR/m³ | Today's gas price (incl. VAT) |
| `sensor.electricity_rate_from_tariff` | EUR/kWh | Base rate from your tariff product (disabled by default) |

The **current hour** sensor also exposes a `prices` attribute containing today's full hourly price schedule as a list of `{start, price}` objects, compatible with custom dashboards and automations.

## Automations

Example: notify when the next hour is cheap:

```yaml
automation:
  - alias: "Cheap electricity next hour"
    trigger:
      - platform: numeric_state
        entity_id: sensor.electricity_price_next_hour
        below: 0.10
    action:
      - service: notify.mobile_app
        data:
          message: "Cheap electricity next hour: {{ states('sensor.electricity_price_next_hour') }} EUR/kWh"
```

## Update interval

Data is refreshed every 30 minutes. Electricity prices update hourly on the EPEX spot market; tomorrow's prices become available around 15:00.

## Troubleshooting

Enable debug logging in `configuration.yaml` to inspect raw API responses:

```yaml
logger:
  default: warning
  logs:
    custom_components.eneco_tariffs: debug
```

The coordinator logs the full raw API response under the `raw` key, which is useful for reporting issues or understanding what data Eneco returns for your account.

## Disclaimer

This integration is not affiliated with or endorsed by Eneco. It uses the same private API as the Mijn Eneco web application. API endpoints or authentication may change without notice.
