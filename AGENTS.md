# Kestra SNMP Plugin

## What

- Provides plugin components under `io.kestra.plugin.snmp`.
- Includes classes such as `SendInform`, `SnmpVersion`, `SendTrap`.

## Why

- What user problem does this solve? Teams need to send SNMP traps or informs for network monitoring from orchestrated workflows instead of relying on manual console work, ad hoc scripts, or disconnected schedulers.
- Why would a team adopt this plugin in a workflow? It keeps SNMP steps in the same Kestra flow as upstream preparation, approvals, retries, notifications, and downstream systems.
- What operational/business outcome does it enable? It reduces manual handoffs and fragmented tooling while improving reliability, traceability, and delivery speed for processes that depend on SNMP.

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
