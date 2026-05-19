# SN360 Desktop Agent — udev integration (D2.2)

This directory ships the udev rule template and helper binary
launcher used by the USB / removable-media policy
enforcement.

## Layout

| File | Installs to | Owner |
|------|-------------|-------|
| `99-sn360-device-control.rules` | `/usr/lib/udev/rules.d/99-sn360-device-control.rules` | `root:root 0644` |
| `sn360-device-control-helper` (binary, built from `crates/sda-device-control` with `--features linux-helper`) | `/usr/lib/sn360-desktop-agent/sn360-device-control-helper` | `root:root 0755` |

## Decision flow

1. The Linux kernel publishes a `udev` `add` event for the device.
2. `systemd-udevd` matches the rule and runs the helper with the
   device attributes in its environment block (`SUBSYSTEM`,
   `ID_USB_VENDOR_ID`, `ID_USB_MODEL_ID`, `ID_SERIAL_SHORT`,
   `DEVPATH`, …).
3. The helper builds a `DeviceCandidate`, opens the agent's
   Unix-domain socket (default
   `/run/sn360-desktop-agent/usb-policy.sock`), writes a single
   newline-terminated JSON request, and reads the agent's
   newline-terminated JSON response.
4. If the agent returns `Action::Block`, the helper exits with
   code `1`; udisks2 honours the `UDISKS_IGNORE=1` env hint and
   does not auto-mount the device.
5. The agent records every decision (block / allow / audit) onto
   its event bus as an `EventKind::UsbDevicePolicyDecision`
   envelope tagged with `connector_type: "device-control"`. The
   gateway forwards it to OpenSearch under
   `sn360-alerts-{tid}-*`.

## Testing locally

```sh
# Spin up the agent with usb_policy enabled.
sda-agent --config packaging/config/config.yaml

# In another terminal, simulate an attach event:
sudo udevadm test \
    --action=add \
    /sys/bus/usb/devices/3-1
```

The hermetic e2e test in `crates/sda-agent/tests/e2e_device_policy.rs`
exercises the full attach → IPC → decision → audit-record path
without any real hardware.
