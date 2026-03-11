package io.kestra.plugin.snmp;

import java.util.Arrays;
import java.util.List;

import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.OID;

import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@NoArgsConstructor
@SuperBuilder
public abstract class AbstractSnmpTask extends Task {
    @Schema(title = "Resolve target host", description = "Hostname or IP of the SNMP manager; defaults to localhost")
    @Builder.Default
    protected Property<String> host = Property.ofValue("localhost");

    @Schema(title = "Set SNMP manager port", description = "UDP port for traps/informs; defaults to 162")
    @Builder.Default
    protected Property<Integer> port = Property.ofValue(162);

    @Schema(title = "Select SNMP version", description = "One of v1, v2c, v3; defaults to v2c")
    @Builder.Default
    protected Property<String> snmpVersion = Property.ofValue("v2c");

    @Schema(title = "Community string (v1/v2c)", description = "Plaintext community for v1/v2c; ignored for v3")
    protected Property<String> community;

    @Schema(title = "SNMPv3 security settings", description = "Username and optional auth/privacy protocols required for v3")
    protected Property<V3Security> v3;

    @Schema(title = "Trap or notification OID", description = "OID for the trap/inform type; required")
    @NotNull
    protected Property<String> trapOid;

    @Schema(title = "Additional varbinds", description = "List of extra OID/value pairs appended to the PDU")
    protected Property<List<VarBind>> bindings;

    @Schema(title = "Timeout (ms)", description = "Transport timeout per send; defaults to 1500 ms")
    @Builder.Default
    protected Property<Integer> timeoutMs = Property.ofValue(1500);

    public static int toSecLevel(AbstractSnmpTask.V3Security sec) {
        boolean auth = sec.getAuthProtocol() != null && !sec.getAuthProtocol().isBlank();
        boolean priv = sec.getPrivProtocol() != null && !sec.getPrivProtocol().isBlank();
        if (auth && priv)
            return SecurityLevel.AUTH_PRIV;
        if (auth)
            return SecurityLevel.AUTH_NOPRIV;
        return SecurityLevel.NOAUTH_NOPRIV;
    }

    @Getter
    @AllArgsConstructor
    public enum AuthProtocol {
        MD5(AuthMD5.ID),
        SHA(AuthSHA.ID),
        SHA224(AuthHMAC128SHA224.ID),
        SHA256(AuthHMAC192SHA256.ID),
        SHA384(AuthHMAC256SHA384.ID),
        SHA512(AuthHMAC384SHA512.ID);

        private final OID oid;

        public static OID fromString(String name) {
            if (name == null)
                return null;
            return Arrays.stream(values())
                .filter(p -> p.name().equalsIgnoreCase(name))
                .map(AuthProtocol::getOid)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported auth protocol: " + name));
        }
    }

    @Getter
    @AllArgsConstructor
    public enum PrivProtocol {
        DES(PrivDES.ID),
        AES128(PrivAES128.ID),
        AES192(PrivAES192.ID),
        AES256(PrivAES256.ID);

        private final OID oid;

        public static OID fromString(String name) {
            if (name == null)
                return null;
            return Arrays.stream(values())
                .filter(p -> p.name().equalsIgnoreCase(name))
                .map(PrivProtocol::getOid)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported privacy protocol: " + name));
        }
    }

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class VarBind {
        @NotBlank
        @Schema(title = "OID", description = "OID of the variable binding (e.g. 1.3.6.1.2.1.1.3.0)")
        private Property<String> oid;

        @NotNull
        @Schema(title = "Value", description = "String value to send for this OID")
        private Property<String> value;
    }

    @Builder
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class V3Security {
        @NotBlank
        @Schema(title = "Username", description = "SNMPv3 user name; required when using v3")
        private String username;

        @Schema(title = "Auth protocol", description = "MD5, SHA, SHA224, SHA256, SHA384, SHA512; blank disables authentication")
        private String authProtocol;

        @Schema(title = "Auth password", description = "Password for the chosen auth protocol; optional when auth is disabled")
        private String authPassword;

        @Schema(title = "Privacy protocol", description = "DES, AES128, AES192, AES256; blank disables encryption")
        private String privProtocol;

        @Schema(title = "Privacy password", description = "Password for the chosen privacy protocol; optional when privacy is disabled")
        private String privPassword;
    }
}
