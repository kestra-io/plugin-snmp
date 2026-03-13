# Kestra SNMP Plugin

## What

description = 'Plugin SNMP for Kestra Exposes 2 plugin components (tasks, triggers, and/or conditions).

## Why

Enables Kestra workflows to interact with SNMP, allowing orchestration of SNMP-based operations as part of data pipelines and automation workflows.

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

### Important Commands

```bash
# Build the plugin
./gradlew shadowJar

# Run tests
./gradlew test

# Build without tests
./gradlew shadowJar -x test
```

### Configuration

All tasks and triggers accept standard Kestra plugin properties. Credentials should use
`{{ secret('SECRET_NAME') }}` — never hardcode real values.

## Agents

**IMPORTANT:** This is a Kestra plugin repository (prefixed by `plugin-`, `storage-`, or `secret-`). You **MUST** delegate all coding tasks to the `kestra-plugin-developer` agent. Do NOT implement code changes directly — always use this agent.
