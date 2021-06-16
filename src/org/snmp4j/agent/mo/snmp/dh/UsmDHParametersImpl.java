/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - UsmDHParametersImpl.java  
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

import org.snmp4j.agent.MOAccess;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.dh.DHGroups;
import org.snmp4j.security.dh.DHParameters;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.math.BigInteger;

/**
 * The {@link UsmDHParametersImpl} class holds the Diffie Hellman parameters for doing a Diffie-Hellman key agreement.
 *
 * @author Frank Fock
 * @since 3.0
 */
public class UsmDHParametersImpl extends MOScalar<OctetString> {

    private DHParameters dhParameters;

    /**
     * Create a {@link DHParameters} instance that uses the Oakeley Group 1 Diffie Hellman parameters defined in
     * RFC 2409 (see also {@link DHGroups}).
     * @param id
     *    the instance OID of the scalar instance (last sub-identifier should be
     *    zero).
     * @param access
     *    the maximum access level supported by this instance.
     * @param value
     *    the initial value that defines the parameters as BER encoded OCTET STRING,
     *    see {@link #decodeBER(OctetString)}.
     */
    public UsmDHParametersImpl(OID id, MOAccess access, OctetString value) {
        super(id, access, value);
        if (value != null && value.length() > 0) {
            try {
                decodeBER(value);
            } catch (IOException e) {
                throw new IllegalArgumentException(value.toHexString());
            }
        }
        else {
            dhParameters = new DHParameters(DHGroups.P1, DHGroups.G, AuthMD5.KEY_LENGTH * 8);
        }
    }

    public DHParameters getDHParamters() {
        return dhParameters;
    }

    /**
     * Encode this parameter set as BER octet string.
     * @return
     *    the PKCS#3 encoded parameter octet string. If the encoding fails, {@code null} is returned.
     */
    public OctetString encodeBER() {
        BigInteger prime = dhParameters.getPrime();
        BigInteger generator = dhParameters.getGenerator();
        int privateValueLength = dhParameters.getPrivateValueLength();

        return DHParameters.encodeBER(prime, generator, privateValueLength);
    }

    public void decodeBER(OctetString berValue) throws IOException {
        dhParameters = DHParameters.getDHParametersFromBER(berValue);
    }

    @Override
    public OctetString getValue() {
        return encodeBER();
    }

    @Override
    public String toString() {
        return "UsmDHParametersImpl{" + dhParameters +
                '}';
    }
}
