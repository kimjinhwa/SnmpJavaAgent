/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - RowIndexComparator.java  
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


package org.snmp4j.agent.mo.util;

import org.snmp4j.agent.mo.MOTableRow;

import java.util.Comparator;

/**
 * Compares two {@link org.snmp4j.agent.mo.MOTableRow} instances by their
 * index {@link org.snmp4j.smi.OID}.
 */
public class RowIndexComparator implements Comparator<MOTableRow> {

  @Override
  public int compare(MOTableRow o1, MOTableRow o2) {
    return o1.getIndex().compareTo(o2.getIndex());
  }
}
