package io.kestra.plugin.snmp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

@SuperBuilder
@EqualsAndHashCode
@ToString
@Getter
@NoArgsConstructor
@Schema(
    title = "Send an SNMP Inform (acknowledged notification)",
    description = "Constructs and sends an SNMP v2c/v3 INFORM to a manager (host:port). Unlike traps, informs expect an acknowledgment from the manager."
)
@Plugin(
    examples = {
        @Example(
            title = "Send SNMP v2c inform",
            full = true,
            code = """
                id: snmp-inform-test
                namespace: monitoring

                tasks:
                  - id: inform
                    type: io.kestra.plugin.snmp.SendInform
                    host: "snmp.manager.local"
                    port: 162
                    version: "v2c"
                    community: "public"
                    trapOid: "1.3.6.1.4.1.8072.2.3.0.1"
                    bindings:
                      - oid: "1.3.6.1.2.1.1.3.0"
                        value: "9999"
            """
        )
    }
)
public class SendInform extends AbstractSnmpTask implements RunnableTask<SendInform.Output> {
    @Schema(
        title = "Number of retries if no response is received",
        description = "How many times to retry before giving up."
    )
    @Builder.Default
    protected Property<Integer> retries = Property.ofValue(1);

    @Override
    public Output run(RunContext runContext) throws Exception {
        var rHost = runContext.render(this.host).as(String.class).orElse("localhost");
        var rPort = runContext.render(this.port).as(Integer.class).orElse(162);
        var rVersion = runContext.render(this.snmpVersion).as(String.class).orElse("v2c");
        var rTrapOid = runContext.render(this.trapOid).as(String.class).orElseThrow();
        var rTimeout = runContext.render(this.timeoutMs).as(Integer.class).orElse(2000);
        var rBindings = runContext.render(this.bindings).asList(AbstractSnmpTask.VarBind.class);
        var rRetries = runContext.render(this.retries).as(Integer.class).orElse(1);

        Address targetAddress = new UdpAddress(rHost + "/" + rPort);
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();

        try (transport; var snmp = new Snmp(transport)) {
            transport.listen();

            PDU pdu = new PDU();
            pdu.setType(PDU.INFORM);
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(rTrapOid)));
            if (rBindings != null) {
                for (AbstractSnmpTask.VarBind b : rBindings) {
                    String oid = runContext.render(b.getOid()).as(String.class).orElse(null);
                    String value = runContext.render(b.getValue()).as(String.class).orElse(null);
                    if (oid != null && value != null) {
                        pdu.add(new VariableBinding(new OID(oid), new OctetString(value)));
                    }
                }
            }

            Target<?> target;
            if (rVersion.equalsIgnoreCase("v2c")) {
                CommunityTarget cTarget = new CommunityTarget();
                cTarget.setAddress(targetAddress);
                cTarget.setCommunity(new OctetString(runContext.render(this.community).as(String.class).orElse("public")));
                cTarget.setRetries(rRetries);
                cTarget.setTimeout(rTimeout);
                cTarget.setVersion(SnmpConstants.version2c);
                target = cTarget;
            } else if (rVersion.equalsIgnoreCase("v3")) {
                USM usm = new USM(SecurityProtocols.getInstance(),
                    new OctetString(MPv3.createLocalEngineID()), 0);
                SecurityModels.getInstance().addSecurityModel(usm);

                var v3sec = runContext.render(this.v3).as(AbstractSnmpTask.V3Security.class)
                    .orElseThrow(() -> new IllegalArgumentException("v3 settings required"));

                snmp.getUSM().addUser(new OctetString(v3sec.getUsername()),
                    new UsmUser(new OctetString(v3sec.getUsername()),
                        AbstractSnmpTask.AuthProtocol.fromString(v3sec.getAuthProtocol()),
                        v3sec.getAuthPassword() != null ? new OctetString(v3sec.getAuthPassword()) : null,
                        AbstractSnmpTask.PrivProtocol.fromString(v3sec.getPrivProtocol()),
                        v3sec.getPrivPassword() != null ? new OctetString(v3sec.getPrivPassword()) : null));

                UserTarget uTarget = new UserTarget();
                uTarget.setAddress(targetAddress);
                uTarget.setRetries(rRetries);
                uTarget.setTimeout(rTimeout);
                uTarget.setVersion(SnmpConstants.version3);
                uTarget.setSecurityLevel(AbstractSnmpTask.toSecLevel(v3sec));
                uTarget.setSecurityName(new OctetString(v3sec.getUsername()));
                target = uTarget;
            } else {
                throw new IllegalArgumentException("INFORM supported only for v2c/v3.");
            }

            ResponseEvent<?> ack = snmp.send(pdu, target);

            runContext.logger().info("Sent INFORM to {}:{}", rHost, rPort);

            boolean success = ack != null && ack.getResponse() != null && ack.getResponse().getErrorStatus() == PDU.noError;

            return Output.builder()
                .acknowledged(success)
                .error(success ? null : (ack != null && ack.getResponse() != null ? ack.getResponse().getErrorStatusText() : null))
                .responseText(ack != null && ack.getResponse() != null ? ack.getResponse().toString() : null)
                .build();
        }
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "Whether the INFORM was acknowledged by the SNMP manager"
        )
        private final boolean acknowledged;

        @Schema(
            title = "Error text if the INFORM was not acknowledged"
        )
        private final String error;

        @Schema(
            title = "SNMP response"
        )
        private final String responseText;
    }
}