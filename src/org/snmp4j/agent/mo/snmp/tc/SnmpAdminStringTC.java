/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - SnmpAdminStringTC.java  
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
package org.snmp4j.agent.mo.snmp.tc;

import org.snmp4j.agent.MOAccess;
import org.snmp4j.agent.mo.MOColumn;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.snmp.SnmpFrameworkMIB;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

/**
 * Created by fock on 31.01.2015.
 */
public class SnmpAdminStringTC implements TextualConvention<OctetString> {

  @Override
  public String getModuleName() {
    return SnmpFrameworkMIB.MODULE_NAME;
  }

  @Override
  public String getName() {
    return SnmpFrameworkMIB.SNMPADMINSTRING;
  }

  @Override
  public MOScalar<OctetString> createScalar(OID oid, MOAccess access, OctetString value) {
    return null;
  }

  @Override
  public MOColumn<OctetString> createColumn(int columnID, int syntax, MOAccess access, OctetString defaultValue, boolean mutableInService) {
    return null;
  }

  @Override
  public OctetString createInitialValue() {
    return null;
  }
}
