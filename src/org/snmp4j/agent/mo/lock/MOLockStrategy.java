/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOLockStrategy.java  
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
package org.snmp4j.agent.mo.lock;

import org.snmp4j.agent.MOQuery;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.request.SubRequest;

/**
 * The {@code MOLockStrategy} interface defines a strategy for locking {@link org.snmp4j.agent.ManagedObject}
 * instances when they are accessed through a {@link org.snmp4j.agent.MOServer}.
 *
 * @author Frank Fock
 * @since 2.4.0
 */
public interface MOLockStrategy {

    /**
     * Check if the server access to the provided managed object needs a lock.
     *
     * @param managedObjectLookedUp
     *         the ManagedObject instance that is looked up and potentially accessed.
     * @param query
     *         the query on which behalf the lookup took place. It also signals with
     *         {@link MOQuery#isWriteAccessQuery()} whether a write access is intended or not.
     *
     * @return {@code true} if a lock is required to access the provided managed object,
     * {@code false} otherwise.
     */
    boolean isLockNeeded(ManagedObject<?> managedObjectLookedUp, MOQuery query);

}
