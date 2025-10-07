package io.kestra.plugin.snmp;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.VoidOutput;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@KestraTest
class SendTrapTest {
    @Inject
    RunContextFactory runContextFactory;

    @Test
    void testSendV2Trap() throws Exception {
        SendTrap trapTask = SendTrap.builder()
            .host(Property.ofValue("localhost"))
            .port(Property.ofValue(162))
            .snmpVersion(Property.ofValue("v2c"))
            .community(Property.ofValue("public"))
            .trapOid(Property.ofValue("1.3.6.1.4.1.8072.2.3.0.1"))
            .bindings(Property.ofValue(List.of(
                SendTrap.VarBind.builder()
                    .oid(Property.ofValue("1.3.6.1.2.1.1.3.0"))
                    .value(Property.ofValue("12345"))
                    .build(),
                SendTrap.VarBind.builder()
                    .oid(Property.ofValue("1.3.6.1.2.1.1.5.0"))
                    .value(Property.ofValue("kestra-agent"))
                    .build()
            )))
            .build();

        VoidOutput output = trapTask.run(runContextFactory.of());
    }
}
