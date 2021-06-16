/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOPriorityProvider.java  
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

package org.snmp4j.agent.mo;

import org.snmp4j.agent.ManagedObject;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.util.SortedMap;

/**
 * {@code MOPriorityProvider} is an object (often a {@link org.snmp4j.agent.ManagedObject}) that defines
 * a prioritisation of other {@link org.snmp4j.agent.ManagedObject}s. This prioritisation can be used to
 * define the order for storing and especially restoring and initializing {@link org.snmp4j.agent.ManagedObject}s
 * by {@link org.snmp4j.agent.io.MOPersistenceProvider} instances.
 *
 * @author Frank Fock
 * @since 3.5.0
 */
public interface MOPriorityProvider {

    /**
     * Returns a sorted map that maps object identifiers to a integer based priority where lesser numbers
     * represent higher priority, i.e. earlier processing in store and restore operations.
     * The {@link OID}s represent the lower bound of the {@link org.snmp4j.agent.MOScope} of
     * {@link org.snmp4j.agent.ManagedObject}s or any of their parent sub-trees.
     *
     * @param context
     *    the SNMPv3 context for which the boot managed object that stores the priority information is to e returned.
     *    {@code null} and the empty (size 0) string represent the default context.
     * @return
     *    a sorted map of OID to zero based priorities.
     */
    SortedMap<OID, Integer> getPriorityMap(OctetString context);

    /**
     * Returns the {@link org.snmp4j.agent.ManagedObject} that stores the priority information and therefore needs to be
     * stored/restored first to determine {@link #getPriorityMap(OctetString)} for the provided context.
     * @param context
     *    the SNMPv3 context for which the boot managed object that stores the priority information is to e returned.
     *    {@code null} and the empty (size 0) string represent the default context.
     * @return the {@code MOScope} that identifies this managed object.
     */
    ManagedObject<?> getBootManagedObject(OctetString context);
}
