# Eneco Dynamic Tariffs

A [HACS](https://hacs.xyz) integration for Home Assistant that fetches dynamic electricity and gas prices from [Eneco](https://www.eneco.nl).

## Requirements

- A Mijn Eneco account with a dynamic energy contract (Eneco Dynamisch)
- Home Assistant 2026.1 or newer
- HACS installed

## Installation

1. In HACS, go to **Integrations** → click the three-dot menu → **Custom repositories**
2. Add `https://github.com/SjamonDaal/eneco-dynamic-tariffs` and select category **Integration**
3. Install **Eneco Dynamic Tariffs** and restart Home Assistant
4. Go to **Settings → Devices & Services → Add Integration** and search for **Eneco Dynamic Tariffs**
5. Enter your Mijn Eneco email address and password
6. If prompted, enter the one-time code sent to your email

## Sensors

| Entity | Unit | Description |
|---|---|---|
| Electricity Price (current hour) | EUR/kWh | All-in price incl. VAT for the current hour |
| Electricity Price (next hour) | EUR/kWh | All-in price incl. VAT for the next hour |
| Gas Price | EUR/m³ | Today's all-in gas price incl. VAT |
| Electricity Rate (from tariff) | EUR/kWh | Fixed commercial component (disabled by default) |

### Attributes

The **current hour** and **next hour** sensors expose:
- `rating` — `cheap`, `average`, or `expensive` (as rated by Eneco)

The **current hour** sensor also exposes:
- `prices` — full hourly price schedule for today as a list of `{start, price, rating}` objects, where `start` is a UTC ISO timestamp

## Dashboard

Example price chart using [ApexCharts Card](https://github.com/RomRider/apexcharts-card):

```yaml
type: custom:apexcharts-card
graph_span: 24h
span:
  start: day
now:
  show: true
  label: Nu
header:
  show: true
  title: Stroomprijs vandaag (€/kWh)
series:
  - entity: sensor.eneco_dynamic_tariffs_electricity_price_current_hour
    stroke_width: 2
    float_precision: 3
    type: column
    opacity: 1
    data_generator: |
      return entity.attributes.prices.map((record) => {
        return [new Date(record.start).getTime(), record.price];
      });
yaxis:
  - id: Prijs
    decimals: 2
```

Tomorrow's prices (available after ~15:00):

```yaml
type: custom:apexcharts-card
graph_span: 24h
span:
  start: day
  offset: +1d
now:
  show: true
  label: Nu
header:
  show: true
  title: Stroomprijs morgen (€/kWh)
series:
  - entity: sensor.eneco_dynamic_tariffs_electricity_price_current_hour
    stroke_width: 2
    float_precision: 3
    type: column
    opacity: 1
    data_generator: |
      return entity.attributes.prices_tomorrow.map((record) => {
        return [new Date(record.start).getTime(), record.price];
      });
yaxis:
  - id: Prijs
    decimals: 2
```

## Automations

Example: notify when the next hour is cheap:

```yaml
automation:
  - alias: "Cheap electricity next hour"
    trigger:
      - platform: state
        entity_id: sensor.eneco_dynamic_tariffs_electricity_price_next_hour
        attribute: rating
        to: cheap
    action:
      - service: notify.mobile_app
        data:
          message: "Cheap electricity next hour: {{ states('sensor.eneco_dynamic_tariffs_electricity_price_next_hour') }} EUR/kWh"
```

## Update interval

Data is refreshed every 30 minutes. Electricity prices update hourly on the EPEX spot market; tomorrow's prices become available around 15:00.

## Troubleshooting

Enable debug logging in `configuration.yaml`:

```yaml
logger:
  default: warning
  logs:
    custom_components.eneco_tariffs: debug
```

## Disclaimer

This integration is not affiliated with or endorsed by Eneco. It uses the same private API as the Mijn Eneco web application. API endpoints or authentication may change without notice.
