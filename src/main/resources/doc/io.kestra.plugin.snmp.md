# How to use the SNMP plugin

Send SNMP traps and inform notifications from Kestra flows.

## Common properties

Set `host` (default `localhost`) and `port` (default `162`). Set `snmpVersion` to `v2c` (default) or `v3`. For SNMPv2c, set `community`. For SNMPv3, configure the `v3` object with `username` (required), `authProtocol` and `authPassword` for authentication, and `privProtocol` and `privPassword` for encryption. Set `timeoutMs` to control the send timeout (default 1500 ms). Apply connection properties globally with [plugin defaults](https://kestra.io/docs/workflow-components/plugin-defaults).

## Tasks

`SendTrap` sends a fire-and-forget SNMP trap — set `trapOid` (required). Add variable bindings via `bindings` (a list of objects with `oid` and `value`).

`SendInform` sends an SNMP inform and waits for an acknowledgement — same properties as `SendTrap` plus `retries` (default 1). The output includes `acknowledged` (boolean), `error`, and `responseText`.
