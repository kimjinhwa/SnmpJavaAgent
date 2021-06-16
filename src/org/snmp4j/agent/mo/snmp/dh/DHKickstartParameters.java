/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DHKickstartParameters.java  
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

import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

/**
 * The {@link DHKickstartParameters} provides the kickstart public parameters needed to
 * initialize Diffie Hellman key exchange. These parameters have to exchanged out-of-band as
 * defined by RFC 2786.
 *
 * @author Frank Fock
 * @since 3.0
 */
public interface DHKickstartParameters {

    /**
     * Gets the security name associated with the kickstart parameters.
     * @return
     *    a SNMPv3 security name.
     */
    OctetString getSecurityName();

    /**
     * Gets the public Diffie Hellman public key for this security name (from the command generator).
     * @return
     *    an octet string.
     */
    OctetString getPublicKey();

    /**
     * As extension for RFC 2786 this parameter allows to select the authentication protocol to use for the
     * kickstart operation. Default is usmHMACMD5AuthProtocol, if {@code null} is returned.
     * @return
     *    the OID of the authentication protocol or {@code null} if the default (usmHMACMD5AuthProtocol) should be
     *    used.
     */
    OID getAuthenticationProtocol();

    /**
     * As extension for RFC 2786 this parameter allows to select the privacy protocol to use for the
     * kickstart operation. Default is usmDESPrivProtocol, if {@code null} is returned.
     * @return
     *    the OID of the privacy protocol or {@code null} if the default (usmDESPrivProtocol) should be
     *    used.
     */
    OID getPrivacyProtocol();

    /**
     * Returns the (optional) role associated with the security name. The actual access rights of the role is
     * implementation dependent but should offer at least the following roles:
     * <pre>
     *     admin - unlimited access
     *     monitor - read-only access
     * </pre>
     * @return
     *    the VACM role that defines the VACM access rights (implementation specific). If no role is provided, the agent
     *    will implementation specific select appropriate access rights.
     */
    String getVacmRole();


    /**
     * Indicates whether an existing user with StorageType nonVolatile or permanent should be replaced by this kickstart
     * user or not.
     * @return
     *    {@code true} if a reset of an existing user is requested, {@code false} otherwise.
     */
    boolean isResetRequested();

}
