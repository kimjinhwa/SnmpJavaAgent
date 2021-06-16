/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DHKeyChangeImpl.java  
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
import org.snmp4j.agent.mo.MOMutableTableRow;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.KeyChange;
import org.snmp4j.agent.mo.snmp.UsmMIB;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthenticationProtocol;
import org.snmp4j.security.SecurityProtocol;
import org.snmp4j.security.dh.DHOperations;
import org.snmp4j.security.dh.DHParameters;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;

import javax.crypto.interfaces.DHPublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * The Diffie Hellman KeyChange object implements a ManagedObject column that implements the DHKeyChange textual
 * convention as defined in RFC 2786.
 *
 * @author Frank Fock
 * @since 3.0
 */
public class DHKeyChangeImpl extends KeyChange {


    private static final LogAdapter LOGGER = LogFactory.getLogger(DHKeyChangeImpl.class);

    private DHParameters dhParameters;
    private DHOperations.KeyType keyType;
    private UsmMIB usmMIB;

    public DHKeyChangeImpl(int columnID, MOAccess access, OctetString defaultValue,
                           DHParameters usmDHParameters, UsmMIB usmMIB,
                           DHOperations.KeyType keyType) {
        super(columnID, access, defaultValue, true);
        this.usmMIB = usmMIB;
        this.keyType = keyType;
        this.dhParameters = usmDHParameters;
    }

    @Override
    public void get(SubRequest<?> subRequest, MOTableRow row, int column) {
        DHKeyInfo keyInfo = getDHKeyInfo(row, column);
        if (keyInfo != null && getAccess().isAccessibleForRead()) {
            if (keyInfo.getKeyPair() == null) {
                try {
                    keyInfo.generatePublicKey(dhParameters);
                } catch (NoSuchAlgorithmException e) {
                    LOGGER.error("Failed to generate DH public key because Diffie-Hellman algorithm is not available", e);
                } catch (InvalidAlgorithmParameterException e) {
                    LOGGER.error("Failed to generate DH public key because of invalid parameters", e);
                }
            }
            subRequest.getVariableBinding().setVariable(DHOperations.derivePublicKey(keyInfo.getKeyPair()));
        }
        else {
            subRequest.getStatus().setErrorStatus(SnmpConstants.SNMP_ERROR_NO_ACCESS);
        }
        subRequest.completed();
    }

    @Override
    public void prepare(SubRequest<?> subRequest, MOTableRow row, MOTableRow changeSet, int column) {
        super.prepare(subRequest, row, changeSet, column);
        DHKeyInfo keyInfo = getDHKeyInfo(row, column);
        if (keyInfo == null || keyInfo.getKeyPair() ==  null || !(keyInfo.getKeyPair().getPublic() instanceof DHPublicKey)) {
            subRequest.setErrorStatus(SnmpConstants.SNMP_ERROR_WRONG_VALUE);
        }
        Variable variable = subRequest.getVariableBinding().getVariable();
        if (variable instanceof OctetString) {
            OctetString yz = (OctetString)variable;
            OctetString yl = DHOperations.derivePublicKey(keyInfo.getKeyPair());
            try {
                OctetString yr = yz.substring(0, yl.length());
                if (!yr.equals(yl)) {
                    subRequest.setErrorStatus(SnmpConstants.SNMP_ERROR_WRONG_VALUE);
                }
            }
            catch (IndexOutOfBoundsException ioobe) {
                subRequest.setErrorStatus(SnmpConstants.SNMP_ERROR_WRONG_VALUE);
            }

        }
    }

    @Override
    public void commit(SubRequest<?> subRequest, MOTableRow row, MOTableRow changeSet, int column) {
        Variable variable = subRequest.getVariableBinding().getVariable();
        if (variable instanceof OctetString && row.getBaseRow() instanceof UsmMIB.UsmTableRow) {
            DHKeyInfo keyInfo = getDHKeyInfo(row, column);
            if (keyInfo == null) {
                subRequest.setErrorStatus(SnmpConstants.SNMP_ERROR_COMMIT_FAILED);
                return;
            }
            OID protocolForKeyChangerotocol = usmMIB.getProtocolForKeyChange(subRequest.getRequest(), row.getIndex(), keyType);
            SecurityProtocol securityProtocol =
                    usmMIB.getSecurityProtocols().getSecurityProtocol(protocolForKeyChangerotocol);
            if (securityProtocol == null) {
                LOGGER.warn("Unknown security protocol '"+protocolForKeyChangerotocol+"' specified for row "+row.getIndex());
                subRequest.setErrorStatus(SnmpConstants.SNMP_ERROR_COMMIT_FAILED);
                return;
            }
            int keyLength = securityProtocol.getMaxKeyLength();
            OctetString yz = (OctetString) variable;
            OctetString yl = DHOperations.derivePublicKey(keyInfo.getKeyPair());
            OctetString z = new OctetString(yz.substring(yl.length(), yz.length()));
            if (keyInfo.getKeyAgreement() == null) {
                keyInfo.getInitializedKeyAgreement();
            }
            byte[] sharedKey = DHOperations.computeSharedKey(keyInfo.getKeyAgreement(), z.getValue(), dhParameters);
            byte[] usmKey = DHOperations.deriveKey(sharedKey, keyLength);
            keyInfo.setUsmKey(usmKey);

            int usmMirrorKeyChangeObjectIndex =
                    UsmMIB.colUsmUserAuthKeyChange + (((column < 2) ? column : column + 1));
            ((MOMutableTableRow)row.getBaseRow()).setValue(usmMirrorKeyChangeObjectIndex, null);

        }
        super.commit(subRequest, row, changeSet, column);
    }

    @Override
    public void undo(SubRequest<?> subRequest, MOTableRow row, int column) {
        DHKeyInfo keyInfo = getDHKeyInfo(row, column);
        if (keyInfo != null) {
            // Deletion is sufficient
            keyInfo.clearUsmKey();
        }
        super.undo(subRequest, row, column);
    }

    DHKeyInfo getDHKeyInfo(MOTableRow row, int columnID) {
        if (row instanceof SnmpUsmDhObjectsMib.UsmDHUserKeyEntryRow) {
            SnmpUsmDhObjectsMib.UsmDHUserKeyEntryRow dhUsmUserEntry = (SnmpUsmDhObjectsMib.UsmDHUserKeyEntryRow) row;
            switch (columnID) {
                case SnmpUsmDhObjectsMib.idxUsmDHUserAuthKeyChange:
                    return dhUsmUserEntry.getAuthKeyChange();
                case SnmpUsmDhObjectsMib.idxUsmDHUserOwnAuthKeyChange:
                    return dhUsmUserEntry.getOwnAuthKeyChange();
                case SnmpUsmDhObjectsMib.idxUsmDHUserPrivKeyChange:
                    return dhUsmUserEntry.getPrivKeyChange();
                case SnmpUsmDhObjectsMib.idxUsmDHUserOwnPrivKeyChange:
                    return dhUsmUserEntry.getOwnPrivKeyChange();
            }
        }
        return null;
    }

}
