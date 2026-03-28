# Example SBOM Files

These files represent a typical IoT gateway firmware project with common embedded components (OpenSSL, FreeRTOS, lwIP, BusyBox, Mosquitto MQTT).

## Try it

```bash
# Validate the SBOM structure
shieldbom validate examples/smart-gateway-firmware.spdx.json

# Scan for vulnerabilities and license issues
shieldbom scan examples/smart-gateway-firmware.spdx.json

# Same firmware in CycloneDX format
shieldbom scan examples/smart-gateway-firmware.cdx.json

# JSON output for CI pipelines
shieldbom scan examples/smart-gateway-firmware.cdx.json --format json

# SARIF output for GitHub Code Scanning
shieldbom scan examples/smart-gateway-firmware.spdx.json --format sarif
```

## Files

| File | Format | Components |
|------|--------|------------|
| `smart-gateway-firmware.spdx.json` | SPDX 2.3 | 9 (OpenSSL, mbedTLS, FreeRTOS, lwIP, zlib, cJSON, Mosquitto, BusyBox, proprietary firmware) |
| `smart-gateway-firmware.cdx.json` | CycloneDX 1.5 | 8 (same components, CycloneDX format) |

## What to expect

These examples contain components with:
- **Known vulnerabilities** — OpenSSL 3.0.8, BusyBox 1.36.0, and Mosquitto 2.0.15 have published CVEs
- **License conflicts** — GPL-2.0-only (BusyBox) alongside a proprietary firmware component
- **Mixed license types** — Apache-2.0, MIT, BSD-3-Clause, Zlib, EPL-2.0, GPL-2.0-only
