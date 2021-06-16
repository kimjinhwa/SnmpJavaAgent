/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - GenericManagedObject.java  
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
import org.snmp4j.agent.request.SubRequest;

/**
 * The {@code GenericManagedObject} interface marks {@link org.snmp4j.agent.ManagedObject} instances that can be used
 * with any type of {@link org.snmp4j.agent.request.SubRequest}, thus with any type of agent (regular, master, and
 * sub-agent).
 *
 * @author Frank Fock
 * @since 3.1.0
 */
public interface GenericManagedObject extends ManagedObject<SubRequest<?>> {

}
