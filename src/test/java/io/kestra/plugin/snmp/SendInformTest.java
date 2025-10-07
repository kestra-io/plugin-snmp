package io.kestra.plugin.snmp;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@KestraTest
class SendInformTest {
    @Inject
    RunContextFactory runContextFactory;

    @Test
    void testInform() throws Exception {
        SendInform task = SendInform.builder()
            .host(Property.ofValue("localhost"))
            .port(Property.ofValue(162))
            .snmpVersion(Property.ofValue("v2c"))
            .community(Property.ofValue("public"))
            .trapOid(Property.ofValue("1.3.6.1.4.1.8072.2.3.0.1"))
            .bindings(Property.ofValue(List.of(
                AbstractSnmpTask.VarBind.builder().oid(Property.ofValue("1.3.6.1.2.1.1.3.0")).value(Property.ofValue("100")).build()
            )))
            .build();

        SendInform.Output output = task.run(runContextFactory.of());
        assertThat(output.isAcknowledged(), is(true));
    }
}
