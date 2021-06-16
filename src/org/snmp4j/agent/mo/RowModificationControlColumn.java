/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - RowModificationControlColumn.java  
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

import org.snmp4j.agent.request.SubRequest;

/**
 * The {@code RowModificationControlColumn} interface is implemented by {@link MOMutableColumn} classes that
 * control any modifications of the whole row. The control is executed when {@link DefaultMOTable} has finished
 * preparing all modified columns with success by calling the
 * {@link #prepareRow(SubRequest, MOMutableTableRow, MOTableRow)} method.
 *
 * @author Frank Fock
 * @since 2.6.3
 */
public interface RowModificationControlColumn {

    /**
     * Prepares a row for changes described by the supplied change set. If the
     * modification cannot be successfully prepared, the error status of the
     * supplied <code>subRequest</code> should be set to the appropriate error
     * status value.
     * <p>
     * This method is called only once per modified row.
     * @param subRequest
     *    the sub-request that triggered the row change and that can be used
     *    to deny the commit phase by setting its error status.
     * @param currentRow
     *    the current row (yet unmodified).
     * @param changeSet
     *    a MOTableRow instance that represents the state of the row if all
     *    changes have been applied successfully.
     */
    void prepareRow(SubRequest<?> subRequest, MOMutableTableRow currentRow, MOTableRow changeSet);


}
