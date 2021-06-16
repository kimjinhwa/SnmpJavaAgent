/*_############################################################################
  _## 
  _##  SNMP4J - TestUSM.java  
  _## 
  _##  Copyright (C) 2003-2021  Frank Fock (SNMP4J.org)
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

package org.snmp4j.security;

import junit.framework.TestCase;
import org.snmp4j.smi.OctetString;

public class TestUSM extends TestCase {

    public void testAddUser() throws Exception {
        USM usm = new USM();
        SecurityProtocols.getInstance().addDefaultProtocols();
        OctetString userName = new OctetString("user1");
        UsmUser usmUser = new UsmUser(userName, AuthHMAC128SHA224.ID, new OctetString("auth12345678"),
                PrivAES128.ID, new OctetString("priv123445678"));
        UsmUserEntry userEntry1 = usm.getUser(new OctetString(), userName);
        assertNull(userEntry1);

        //we add the user, but the engineId is not known yet
        usm.addUser(new OctetString(userName), new OctetString(), usmUser);
        UsmUserEntry userEntry2 = usm.getUser(new OctetString(), userName);
        assertNotNull(userEntry2);

        OctetString engineId = new OctetString("someEngineID");
        // localisation should take place now
        UsmUserEntry userEntry3 = usm.getUser(engineId, userName);
        assertNotNull(userEntry3);
        assertNotNull(userEntry3.getAuthenticationKey());
        assertNotNull(userEntry3.getPrivacyKey());
    }
}
