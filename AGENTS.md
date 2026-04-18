# Kestra SNMP Plugin

## What

- Provides plugin components under `io.kestra.plugin.snmp`.
- Includes classes such as `SendInform`, `SnmpVersion`, `SendTrap`.

## Why

- This plugin integrates Kestra with SNMP.
- It provides tasks that send SNMP traps or informs for network monitoring.

## How

### Architecture

Single-module plugin. Source packages under `io.kestra.plugin`:

- `snmp`

Infrastructure dependencies (Docker Compose services):

- `snmptrapd`

### Key Plugin Classes

- `io.kestra.plugin.snmp.SendInform`
- `io.kestra.plugin.snmp.SendTrap`

### Project Structure

```
plugin-snmp/
├── src/main/java/io/kestra/plugin/snmp/
├── src/test/java/io/kestra/plugin/snmp/
├── build.gradle
└── README.md
```

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
