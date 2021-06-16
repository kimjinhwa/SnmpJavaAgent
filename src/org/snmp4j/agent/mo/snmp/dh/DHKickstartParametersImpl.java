/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DHKickstartParametersImpl.java  
  _## 
  _##  Copyright (C) 2005-2021  Frank Fock (SNMP4J.org)
  _##  
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##  
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##  
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##  
  _##########################################################################*/

package org.snmp4j.agent.mo.snmp.dh;

import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.dh.DHOperations;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * The {@link DHKickstartParametersImpl} provides the kickstart public parameters needed to
 * initialize Diffie Hellman key exchange. These parameters have to exchanged out-of-band as
 * defined by RFC 2786. This implementation of the {@link DHKickstartParameters} interface provides
 * a static method to create kickstart parameters from a set of properties of the following form:
 * <pre>{@code
 * dh.publicKey.<securityName>=<publicKeyHexFormattedWithoutSeparator>
 * dh.authProtocol.<securityName>=<OID>
 * dh.privProtocol.<securityName>=<OID>
 * dh.vacm.role.<securityName>=<vacmRole>
 * dh.reset.<securityName>=true|false
 * }
 * </pre>
 * @author Frank Fock
 * @since 3.0
 */
public class DHKickstartParametersImpl implements DHKickstartParameters {

    private OctetString securityName;
    private OctetString publicKey;
    private OID authenticationProtocol = SnmpConstants.usmHMACMD5AuthProtocol;
    private OID privacyProtocol = SnmpConstants.usmDESPrivProtocol;
    private String vacmRole;
    private boolean resetRequested;

    /**
     * Create a Diffie Hellman kickstart parameter set with the provided authentication and privacy protocols.
     * @param securityName
     *   the security name of the provisioned user.
     * @param publicKey
     *   the Diffie Hellman public key as defined by RFC 2786.
     * @param authenticationProtocol
     *   the OID of the authentication protocol to be used by this user.
     * @param privacyProtocol
     *   the OID of the privacy protocol to be used by this user.
     * @param vacmRole
     *   the agent implementation specific VACM role that defines the access rights associated with the user.
     * @param resetRequested
     *   if {@code true}, existing nonVolatile or permanent USM user with the same security name will be replaced
     *   by this new kickstart user.
     */
    public DHKickstartParametersImpl(OctetString securityName, OctetString publicKey,
                                     OID authenticationProtocol, OID privacyProtocol, String vacmRole,
                                     boolean resetRequested) {
        this.securityName = securityName;
        this.publicKey = publicKey;
        this.authenticationProtocol = authenticationProtocol;
        this.privacyProtocol = privacyProtocol;
        this.vacmRole = vacmRole;
        this.resetRequested = resetRequested;
    }

    /**
     * Create a Diffie Hellman kickstart parameter set with default authentication (MD5) and privacy (DES) protocols.
     * @param securityName
     *   the security name of the provisioned user.
     * @param publicKey
     *   the Diffie Hellman public key as defined by RFC 2786.
     */
    public DHKickstartParametersImpl(OctetString securityName, OctetString publicKey) {
        this.securityName = securityName;
        this.publicKey = publicKey;
    }

    @Override
    public OctetString getSecurityName() {
        return securityName;
    }

    @Override
    public OctetString getPublicKey() {
        return publicKey;
    }

    @Override
    public OID getAuthenticationProtocol() {
        return authenticationProtocol;
    }

    @Override
    public OID getPrivacyProtocol() {
        return privacyProtocol;
    }

    @Override
    public String getVacmRole() {
        return vacmRole;
    }

    /**
     * Indicates whether an existing user with StorageType nonVolatile or permanent should be replaced by this kickstart
     * user or not.
     *
     * @return {@code true} if a reset of an existing user is requested, {@code false} otherwise.
     */
    @Override
    public boolean isResetRequested() {
        return resetRequested;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DHKickstartParametersImpl that = (DHKickstartParametersImpl) o;

        if (!getSecurityName().equals(that.getSecurityName())) return false;
        return getPublicKey().equals(that.getPublicKey());
    }

    @Override
    public int hashCode() {
        int result = getSecurityName().hashCode();
        result = 31 * result + getPublicKey().hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "DHKickstartParametersImpl{" +
                "securityName=" + securityName +
                ", publicKey=" + publicKey +
                ", authenticationProtocol=" + authenticationProtocol +
                ", privacyProtocol=" + privacyProtocol +
                ", vacmRole='" + vacmRole + '\'' +
                ", resetRequested=" + resetRequested +
                '}';
    }

    public static List<DHKickstartParameters> readFromProperties(String propertyPrefix, Properties properties) {
        ArrayList<DHKickstartParameters> kickstartParameters = new ArrayList<>();
        for (Map.Entry<Object,Object> entry : properties.entrySet()) {
            if (entry.getKey().toString().startsWith(propertyPrefix + DHOperations.DH_PUBLIC_KEY_PROPERTY)) {
                String userName = entry.getKey().toString().substring(propertyPrefix.length() +
                        DHOperations.DH_PUBLIC_KEY_PROPERTY.length());
                String publicKeyHex = entry.getValue().toString();
                DHKickstartParametersImpl dhKickstartParameters =
                        new DHKickstartParametersImpl(new OctetString(userName),
                                OctetString.fromString(publicKeyHex, 16));
                String authProtocol = properties.getProperty(propertyPrefix +
                        DHOperations.DH_AUTH_PROTOCOL_PROPERTY +userName, null);
                if (authProtocol != null) {
                    dhKickstartParameters.authenticationProtocol = new OID(authProtocol);
                }
                String privProtocol = properties.getProperty(propertyPrefix +
                        DHOperations.DH_PRIV_PROTOCOL_PROPERTY +userName, null);
                if (privProtocol != null) {
                    dhKickstartParameters.privacyProtocol = new OID(privProtocol);
                }
                dhKickstartParameters.vacmRole = properties.getProperty(propertyPrefix +
                        DHOperations.DH_VACM_ROLE_PROPERTY + userName, null);
                dhKickstartParameters.resetRequested = Boolean.parseBoolean(properties.getProperty(propertyPrefix +
                        DHOperations.DH_RESET_PROPERTY + userName, null));
                kickstartParameters.add(dhKickstartParameters);
            }
        }
        return kickstartParameters;
    }
}
