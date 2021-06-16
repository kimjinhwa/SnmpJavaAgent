/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DHKeyInfo.java  
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

import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.security.dh.DHOperations;
import org.snmp4j.security.dh.DHParameters;

import javax.crypto.KeyAgreement;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class DHKeyInfo {

    private LogAdapter LOGGER = LogFactory.getLogger(DHKeyInfo.class);

    private KeyPair keyPair;
    private KeyAgreement keyAgreement;
    private DHParameters keyParameters;
    private byte[] usmKey;


    DHKeyInfo() {
    }

    KeyPair getKeyPair() {
        return keyPair;
    }

    KeyAgreement getKeyAgreement() {
        return keyAgreement;
    }

    DHParameters getKeyParameters() {
        return keyParameters;
    }

    public KeyPair generatePublicKey(DHParameters dhParameters)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        keyParameters = dhParameters;
        keyPair = DHOperations.generatePublicKey(keyParameters);
        return keyPair;
    }

    public KeyAgreement getInitializedKeyAgreement() {
        keyAgreement = DHOperations.getInitializedKeyAgreement(keyPair);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Created KeyAgreement: "+keyAgreement);
        }
        return keyAgreement;
    }

    public byte[] getSharedKey() {
        return DHOperations.computeSharedKey(keyAgreement, DHOperations.keyToBytes(keyPair.getPublic()), keyParameters);
    }

    public byte[] getUsmKey() {
        return usmKey;
    }

    public void setUsmKey(byte[] usmKey) {
        this.usmKey = usmKey;
    }

    public void clearUsmKey() {
        if (usmKey !=  null) {
            Arrays.fill(usmKey, (byte)0);
            this.usmKey = null;
        }
    }

    public boolean isKeyChangePending() {
        return usmKey != null;
    }

}
