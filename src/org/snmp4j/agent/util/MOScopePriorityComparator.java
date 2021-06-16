/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOScopePriorityComparator.java  
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

package org.snmp4j.agent.util;

import org.snmp4j.agent.MOScope;
import org.snmp4j.agent.MOScopeComparator;
import org.snmp4j.smi.OID;

import java.util.SortedMap;

/**
 * The {@link MOScopePriorityComparator} applies a sorting on a list of {@link MOScope} instances
 * defined by a priority list. For instances where no priority is set by the priority list,
 * this iterator will return them after the other items in default order defined by
 * {@link org.snmp4j.agent.MOScopeComparator}.
 *
 * @author Frank Fock
 * @since 3.5.0
 * @version 3.5.0
 */
public class MOScopePriorityComparator extends MOScopeComparator {

    private final SortedMap<OID, Integer> priorityMap;

    public MOScopePriorityComparator(SortedMap<OID, Integer> priorityMap) {
        this.priorityMap = priorityMap;
    }

    @Override
    public int compare(MOScope o1, MOScope o2) {
        OID lowerBound1 = o1.getLowerBound();
        OID lowerBound2 = o2.getLowerBound();
        Integer prio1 = getPriority(lowerBound1);
        Integer prio2 = getPriority(lowerBound2);
        if (prio1 == null && prio2 != null) {
            return 1;
        }
        else if ((prio1 != null) && (prio2 == null)) {
            return -1;
        }
        else if (prio1 != null) {
            int result = prio1 - prio2;
            if (result != 0) {
                return result;
            }
        }
        return super.compare(o1, o2);
    }

    private Integer getPriority(OID oid) {
        Integer priority = priorityMap.get(oid);
        if (priority == null) {
            SortedMap<OID, Integer> headMap = priorityMap;
            OID predecessor = null;
            do {
                headMap = headMap.headMap(predecessor == null ? oid : predecessor);
            } while (headMap.size() > 0 && ((predecessor = headMap.lastKey()).size()>0) && !oid.startsWith(predecessor));
            if (predecessor != null && oid.startsWith(predecessor)) {
               return headMap.get(predecessor);
            }
        }
        return priority;
    }
}
