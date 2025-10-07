package io.kestra.plugin.snmp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.models.tasks.VoidOutput;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.snmp4j.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.Arrays;
import java.util.List;

@SuperBuilder
@EqualsAndHashCode
@ToString
@Getter
@NoArgsConstructor
@Schema(
    title = "Send an SNMP trap (event)",
    description = "Constructs and sends an SNMP v1/v2c/v3 trap to a manager (host:port)."
)
@Plugin(
    examples = {
        @Example(
            title = "Send SNMP v2c trap on error",
            full = true,
            code = """
                id: snmp-trap-on-failure
                namespace: monitoring

                tasks:
                  - id: risky
                    type: io.kestra.plugin.scripts.shell.Commands
                    commands:
                      - 'exit 1'

                errors:
                  - id: send-trap
                    type: io.kestra.plugin.snmp.SendTrap
                    host: "snmp.manager.local"
                    port: 162
                    snmpVersion: "v2c"
                    community: "public"
                    trapOid: "1.3.6.1.4.1.8072.2.3.0.1"
                    bindings:
                      - oid: "1.3.6.1.2.1.1.3.0"
                        value: "12345"
                      - oid: "1.3.6.1.4.1.8072.2.3.2.1"
                        value: "FAILED"
            """
        )
    }
)
public class SendTrap extends AbstractSnmpTask implements RunnableTask<VoidOutput> {
    @Override
    public VoidOutput run(RunContext runContext) throws Exception {
        var rHost = runContext.render(this.host).as(String.class).orElse("localhost");
        var rPort = runContext.render(this.port).as(Integer.class).orElse(162);
        var rVersion = runContext.render(this.snmpVersion).as(String.class).orElse("v2c");
        var rTrapOid = runContext.render(this.trapOid).as(String.class).orElseThrow();
        var rTimeout = runContext.render(this.timeoutMs).as(Integer.class).orElse(1500);
        var rBindings = runContext.render(this.bindings).asList(AbstractSnmpTask.VarBind.class);

        Address targetAddress = new UdpAddress(rHost + "/" + rPort);
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();

        try (var snmp = new Snmp(transport)) {
            transport.listen();

            SnmpVersion ver = SnmpVersion.fromString(rVersion);
            SnmpVersion.Built built = ver.build(
                runContext, targetAddress, rTimeout,
                rTrapOid, rBindings,
                runContext.render(this.v3).as(AbstractSnmpTask.V3Security.class).orElse(null),
                runContext.render(this.community).as(String.class).orElse("public"),
                snmp
            );

            snmp.send(built.getPdu(), built.getTarget());;

            runContext.logger().info("SNMP trap sent to {}:{}", rHost, rPort);

            return null;
        }
    }
}
