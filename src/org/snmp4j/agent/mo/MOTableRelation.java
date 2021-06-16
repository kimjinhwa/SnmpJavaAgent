/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOTableRelation.java  
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

/**
 * The <code>MOTableRelation</code> class models table relations like sparse
 * table relationship and augmentation. This class implements the augmentation
 * relationship. In order to implement a sparse table relationship, sub-classing
 * <code>MOTableRelation</code> is needed and the methods
 * {@link #hasDependentRow} and {@link #getDependentIndexes} must be overwritten
 * then.
 *
 * @param <BaseRow>
 *         The row type of the base table.
 * @param <DependentRow>
 *         The row type of the dependent table.
 *
 * @author Frank Fock
 * @version 3.0.0
 */
public class MOTableRelation<BaseRow extends MOTableRow, DependentRow extends MOTableRow> {

    @SuppressWarnings("rawtypes")
    private MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> baseTable;
    @SuppressWarnings("rawtypes")
    private MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> dependentTable;
    private MOTableRowListener<BaseRow> relationShipListener;

    /**
     * Creates a table relation from a base table and the dependent table.
     * To actually set up the relationship between those tables
     * {@link #createRelationShip()} needs to be called.
     *
     * @param baseTable
     *         the base table.
     * @param dependentTable
     *         the dependent (augmenting) table.
     */
    @SuppressWarnings("rawtypes")
    public MOTableRelation(MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> baseTable,
                           MOTable<DependentRow, ? extends MOColumn,
                                   ? extends MOTableModel<DependentRow>> dependentTable) {
        this.baseTable = baseTable;
        this.dependentTable = dependentTable;
    }

    /**
     * Actually sets up the relationship between base and dependent table by
     * adding this instance as row listener to the base table.
     */
    public void createRelationShip() {
        this.baseTable.addMOTableRowListener(createRelationShipListener());
    }

    /**
     * Removes the relationship between base and dependent table by
     * removing this instance as row listener from the base table.
     *
     * @since 3.0.0
     */
    public void removeRelationShip() {
        if (relationShipListener != null) {
            this.baseTable.removeMOTableRowListener(relationShipListener);
        }
    }

    protected MOTableRowListener<BaseRow> createRelationShipListener() {
        this.relationShipListener = new RelationShipListener();
        return this.relationShipListener;
    }

    /**
     * Indicates whether the specified baseTableRow has any dependent rows.
     * By default this method returns <code>true</code> because the default
     * implementation represents an augmentation relationship.
     * Overwrite this method in a sub-class to implement a sparse table
     * relationship.
     *
     * @param baseTableRow
     *         a row of the base table.
     *
     * @return <code>true</code> if the row has dependent rows.
     */
    public boolean hasDependentRow(BaseRow baseTableRow) {
        // by default this is an augmentation
        // overwrite in a subclass to implement sparse relationship
        return true;
    }

    /**
     * Returns the dependent indexes for the specified base row. By default, this
     * method returns the base rows index in a one element array, because
     * the default implementation represents an augmentation relationship.
     * Overwrite this method in a sub-class to implement a sparse table
     * relationship.
     *
     * @param baseRow
     *         a row of the base table.
     *
     * @return an array of row index values of the dependent rows.
     */
    public OID[] getDependentIndexes(BaseRow baseRow) {
        // by default this is an augmentation
        // overwrite in a subclass to implement sparse relationship
        return new OID[]{baseRow.getIndex()};
    }

    @SuppressWarnings("rawtypes")
    public MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> getBaseTable() {
        return baseTable;
    }

    @SuppressWarnings("rawtypes")
    public MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> getDependentTable() {
        return dependentTable;
    }

    public MOTableRowListener<BaseRow> getRelationShipListener() {
        return relationShipListener;
    }

    /**
     * Adds all dependent rows for the specified base table row to the dependent
     * table. This method is automatically called if {@link #createRelationShip()}
     * has been called.
     *
     * @param baseTableRow
     *         a row of the base table.
     */
    protected void addDependentRows(BaseRow baseTableRow) {
        OID[] indexes = getDependentIndexes(baseTableRow);
        for (OID index : indexes) {
            DependentRow depRow =
                    dependentTable.createRow(index, dependentTable.getDefaultValues());
            depRow.setBaseRow(baseTableRow);
            dependentTable.addRow(depRow);
        }
    }

    /**
     * Update the {@link MOTableRow#getBaseRow()} reference all dependent rows for the specified base table row in
     * the dependent table. This method is automatically called if {@link #createRelationShip()}
     * has been called.
     *
     * @param baseTableRow
     *         a row of the base table.
     */
    protected void updateDependentRows(BaseRow baseTableRow) {
        OID[] indexes = getDependentIndexes(baseTableRow);
        for (OID index : indexes) {
            DependentRow depRow = dependentTable.getModel().getRow(index);
            depRow.setBaseRow(baseTableRow);
        }
    }

    /**
     * Removes all dependent rows for the specified base table row
     * from the dependent table. This method is automatically called if
     * {@link #createRelationShip()} has been called.
     *
     * @param baseTableRow
     *         a row of the base table.
     *
     * @return an array of the removed rows.
     */
    @SuppressWarnings("rawtypes")
    protected MOTableRow[] removeDependentRows(BaseRow baseTableRow) {
        OID[] indexes = getDependentIndexes(baseTableRow);
        MOTableRow[] removedRows = new MOTableRow[indexes.length];
        for (int i = 0; i < indexes.length; i++) {
            removedRows[i] = dependentTable.removeRow(indexes[i]);
        }
        return removedRows;
    }

    protected class RelationShipListener implements MOTableRowListener<BaseRow> {

        public void rowChanged(MOTableRowEvent<BaseRow> event) {
            switch (event.getType()) {
                case MOTableRowEvent.EXISTS:
                case MOTableRowEvent.ADD: {
                    if ((event.getRow() == null) || dependentTable.getModel().containsRow(event.getRow().getIndex())) {
                        if (event.getRow() != null) {
                            // update baseRow reference
                            updateDependentRows(event.getRow());
                        }
                        return;
                    } else if (hasDependentRow(event.getRow())) {
                        addDependentRows(event.getRow());
                    }
                    break;
                }
                case MOTableRowEvent.DELETE: {
                    removeDependentRows(event.getRow());
                }
            }
        }

        @SuppressWarnings("rawtypes")
        public MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> getDependentTable() {
            return dependentTable;
        }
    }
}
