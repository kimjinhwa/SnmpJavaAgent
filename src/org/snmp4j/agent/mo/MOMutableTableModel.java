/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOMutableTableModel.java  
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

import org.snmp4j.smi.OID;

import java.util.List;

/**
 * The {@code MOMutableTableModel} defines the interface for mutable
 * table models. Mutable table models support row creation and deletion through
 * SNMP SET operations.
 *
 * @author Frank Fock
 * @version 3.0.0
 */
public interface MOMutableTableModel<R extends MOTableRow>
    extends MOTableModel<R>, MOTableRowFactory<R> {

  /**
   * Adds a row to the table. If a row with the same index already exists
   * it will be replaced and returned.
   *
   * @param row
   *    the {@code MOTableRow} instance to add.
   * @return
   *    the previous row with the specified index or {@code null} if it
   *    did not have one.
   */
  R addRow(R row);

  /**
   * Removes the row with the specified index from the table and returns it.
   * @param index
   *    the row index of the row to remove.
   * @return
   *    the removed row or {@code null} if the table did not contain such
   *    a row.
   */
  R removeRow(OID index);

  /**
   * Removes all rows.
   */
  void clear();

  /**
   * Remove all rows that do not match the given filter criteria
   * from the model.
   * @param filter
   *    the {@code MOTableRowFilter} that filters out the rows to
   *    delete.
   * @return
   *    a list of the removed rows that did not pass (match) the filter.
   */
  List<R> clear(MOTableRowFilter<R> filter);

  /**
   * Sets the factory instance to be used for creating rows for this model.
   *
   * @param rowFactory
   *    a {@code MOTableRowFactory} instance or {@code null} to
   *    disable row creation.
   */
  void setRowFactory(MOTableRowFactory<R> rowFactory);


  /**
   * Gets the factory instance used for creating rows for this model.
   * @return
   *   the row factory used for creating rows or {@code null} if
   *   row creation is not possible due to a missing factory.
   * @since 2.4.0
   */
  MOTableRowFactory<R> getRowFactory();
}
