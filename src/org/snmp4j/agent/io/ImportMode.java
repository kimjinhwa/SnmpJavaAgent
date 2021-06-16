/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - ImportMode.java  
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

package org.snmp4j.agent.io;

// For JavaDoc only:
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.snmp.StorageType;

/**
 * The definition of import modes for MIB data.
 *
 * @author Frank Fock
 * @version 3.0
 */
public enum ImportMode {

  /**
   * Replaces existing data that has a {@link StorageType#nonVolatile}. Rows of type {@link StorageType#permanent}
   * are updated if a row with the same index exists in the import data for the current {@link ManagedObject} and
   * creates data that does not yet exist.
   * @since 3.0
   */
  restoreChanges,
  /**
   * Replaces existing data, if there is any data available for import for the
   * current {@link ManagedObject} and creates data that does not yet exist.
   */
  replaceCreate,
  /**
   * In contrast to {@link #REPLACE_CREATE}, only existing data is updated
   * or new data is created. Existing data for a {@link ManagedObject} which
   * is not updated through imported data, will not be changed (deleted)
   * during import.
   */
  updateCreate,
  /**
   * Only update existing data. No new instances are created and nothing
   * deleted.
   */
  update,
  /**
   * Only create new instances. No updates at all.
   */
  create;

  /**
   * Replaces existing data that has a {@link StorageType#nonVolatile}. Rows of type {@link StorageType#permanent}
   * are updated if a row with the same index exists in the import data for the current {@link ManagedObject} and
   * creates data that does not yet exist.
   * @since 3.0
   */
  public static final int RESTORE_CHANGES = 0;

  /**
   * Replaces existing data, if there is any data available for import for the
   * current {@link ManagedObject} and creates data that does not yet exist.
   */
  public static final int REPLACE_CREATE = 1;
  /**
   * In contrast to {@link #REPLACE_CREATE}, only existing data is updated
   * or new data is created. Existing data for a {@link ManagedObject} which
   * is not updated through imported data, will not be changed (deleted)
   * during import.
   */
  public static final int UPDATE_CREATE = 2;

  /**
   * Only update existing data. No new instances are created and nothing
   * deleted.
   */
  public static final int UPDATE = 3;

  /**
   * Only create new instances. No updates at all.
   */
  public static final int CREATE = 4;

}
