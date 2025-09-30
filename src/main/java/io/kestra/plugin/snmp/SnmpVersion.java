package io.kestra.plugin.snmp;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.runners.RunContext;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.UserTarget;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Counter64;
import org.snmp4j.smi.Gauge32;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

import java.util.Arrays;
import java.util.List;

@Getter
@AllArgsConstructor
public enum SnmpVersion {
    V1(SnmpConstants.version1) {
        @Override
        public Built build(RunContext runContext, Address addr, int timeout, String trapOid, List<AbstractSnmpTask.VarBind> bindings, AbstractSnmpTask.V3Security sec, String community, Snmp snmp) throws IllegalVariableEvaluationException {
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            addBindings(runContext, pdu, bindings);

            CommunityTarget target = new CommunityTarget();
            target.setAddress(addr);
            target.setCommunity(new OctetString(community));
            target.setRetries(0);
            target.setTimeout(timeout);
            target.setVersion(SnmpConstants.version1);

            return new Built(target, pdu);
        }
    },
    V2C(SnmpConstants.version2c) {
        @Override
        public Built build(RunContext runContext, Address addr, int timeout, String trapOid, List<AbstractSnmpTask.VarBind> bindings, AbstractSnmpTask.V3Security sec, String community, Snmp snmp) throws IllegalVariableEvaluationException {
            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            addBindings(runContext, pdu, bindings);
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(trapOid)));

            CommunityTarget target = new CommunityTarget();
            target.setAddress(addr);
            target.setCommunity(new OctetString(community));
            target.setRetries(0);
            target.setTimeout(timeout);
            target.setVersion(SnmpConstants.version2c);

            return new Built(target, pdu);
        }
    },
    V3(SnmpConstants.version3) {
        @Override
        public Built build(RunContext runContext, Address addr, int timeout, String trapOid, List<AbstractSnmpTask.VarBind> bindings, AbstractSnmpTask.V3Security sec, String community, Snmp snmp) throws IllegalVariableEvaluationException {
            if (sec == null) throw new IllegalArgumentException("v3 settings required");

            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);

            OID authProt = AbstractSnmpTask.AuthProtocol.fromString(sec.getAuthProtocol());
            OID privProt = AbstractSnmpTask.PrivProtocol.fromString(sec.getPrivProtocol());

            snmp.getUSM().addUser(new OctetString(sec.getUsername()),
                new UsmUser(new OctetString(sec.getUsername()),
                    authProt,
                    sec.getAuthPassword() != null ? new OctetString(sec.getAuthPassword()) : null,
                    privProt,
                    sec.getPrivPassword() != null ? new OctetString(sec.getPrivPassword()) : null));

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(trapOid)));
            addBindings(runContext, pdu, bindings);

            UserTarget target = new UserTarget();
            target.setAddress(addr);
            target.setRetries(0);
            target.setTimeout(timeout);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(AbstractSnmpTask.toSecLevel(sec));
            target.setSecurityName(new OctetString(sec.getUsername()));

            return new Built(target, pdu);
        }
    };

    private final int code;

    public abstract Built build(RunContext runContext, Address addr, int timeout, String trapOid, List<AbstractSnmpTask.VarBind> bindings, AbstractSnmpTask.V3Security sec, String community, Snmp snmp) throws IllegalVariableEvaluationException;

    public static SnmpVersion fromString(String s) {
        return Arrays.stream(values())
            .filter(v -> v.name().equalsIgnoreCase(s))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unsupported SNMP snmpVersion: " + s));
    }

    protected static void addBindings(RunContext runContext, PDU pdu, List<AbstractSnmpTask.VarBind> bindings) throws IllegalVariableEvaluationException {
        if (bindings == null) return;
        for (AbstractSnmpTask.VarBind b : bindings) {
            String oid = runContext.render(b.getOid()).as(String.class).orElse(null);
            String value = runContext.render(b.getValue()).as(String.class).orElse(null);

            Variable var = toVariable(value);
            if (var != null) {
                pdu.add(new VariableBinding(new OID(oid), var));
            }
        }
    }

    public static Variable toVariable(String raw) {
        if (raw == null) return null;

        if (raw.matches("^-?\\d+$")) {
            return new Integer32(Integer.parseInt(raw));
        }

        if (raw.matches("^\\d+$")) {
            long l = Long.parseLong(raw);
            if (l <= Integer.MAX_VALUE) return new Gauge32((int) l);
            return new Counter64(l);
        }

        if (raw.matches("^(\\d+\\.)+\\d+$")) {
            return new OID(raw);
        }

        return new OctetString(raw);
    }

    @Getter
    @AllArgsConstructor
    public static class Built {
        private final Target<?> target;
        private final PDU pdu;
    }
}
