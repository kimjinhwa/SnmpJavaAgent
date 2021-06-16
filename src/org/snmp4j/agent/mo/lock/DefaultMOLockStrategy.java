/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DefaultMOLockStrategy.java  
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
import org.snmp4j.agent.UpdatableManagedObject;
import org.snmp4j.agent.request.SubRequest;

/**
 * The <code>DefaultMOLockStrategy</code> implements a simple default locking strategy that
 * requires a lock if a write access on a {@link ManagedObject} is intended or if the managed object
 * accessed is an instance of {@link UpdatableManagedObject}.
 * A managed object server that uses this lock strategy ensures that two concurrently received
 * SET requests will not modify the same managed object at the same time with probably undefined result.
 * In addition, managed objects that need to be updated regularly are protected against access while
 *
 * @author Frank Fock
 * @since 2.4.0
 */
public class DefaultMOLockStrategy implements MOLockStrategy {

    @Override
    public boolean isLockNeeded(ManagedObject<?> managedObjectLookedUp, MOQuery query) {
        return query.isWriteAccessQuery() || (managedObjectLookedUp instanceof UpdatableManagedObject);
    }
}
