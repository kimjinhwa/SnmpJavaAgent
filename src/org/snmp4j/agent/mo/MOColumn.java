/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOColumn.java  
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

import org.snmp4j.agent.*;
import org.snmp4j.smi.*;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.mp.SnmpConstants;

/**
 * The {@code MOColumn} class represents columnar SMI objects. It
 * represents all instances of a table's column not only a single instance
 * (cell).
 * <p>
 * Objects represented by {@code MOColumn} cannot be modified via SNMP,
 * thus {@code MOColumn} supports read-only maximum access only.
 *
 * @author Frank Fock
 * @version 2.6
 * @see MOMutableColumn
 */
public class MOColumn<V extends Variable> implements Comparable<MOColumn<V>> {

    private int columnID;
    private int syntax;
    private MOAccess access;
    @SuppressWarnings("rawtypes")
    private MOTable table;

    /**
     * Creates a read-only column object with the given column and syntax.
     *
     * @param columnID
     *         the column ID which is ID the last sub-identifier of the corresponding
     *         OBJECT-TYPE definition.
     * @param syntax
     *         the syntax of the objects in this column. See {@link SMIConstants} for
     *         possible values.
     */
    public MOColumn(int columnID, int syntax) {
        this.columnID = columnID;
        this.syntax = syntax;
        this.access = MOAccessImpl.ACCESS_READ_ONLY;
    }

    /**
     * Creates a column object with the given column, syntax, and maximum access.
     * Since {@code MOColumn} only supports read-only columns the only
     * reasonable values for {@code access} are 'not-accessible' and
     * 'read-only'. Generally this constructor should not be called directly.
     *
     * @param columnID
     *         the column ID which is ID the last sub-identifier of the corresponding
     *         OBJECT-TYPE definition.
     * @param syntax
     *         the syntax of the objects in this column. See {@link SMIConstants} for
     *         possible values.
     * @param access
     *         the maximum access of the column.
     */
    public MOColumn(int columnID, int syntax, MOAccess access) {
        this.columnID = columnID;
        this.syntax = syntax;
        if (access == null) {
            throw new NullPointerException("Access must be specified");
        }
        this.access = access;
    }

    public void setColumnID(int columnID) {
        this.columnID = columnID;
    }

    public void setSyntax(int syntax) {
        this.syntax = syntax;
    }

    public void setAccess(MOAccess access) {
        this.access = access;
    }

    /**
     * Sets the table instance this columnar object is contained in. This method
     * should be called by {@link MOTable} instance to register the table with
     * the column.
     *
     * @param table
     *         the {@code MOTable} instance where this column is contained in.
     * @param <R>
     *         the {@link MOTableRow} type supported by the table.
     */
    @SuppressWarnings("rawtypes")
    public <R extends MOTableRow> void setTable(MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table) {
        this.table = table;
    }

    public int getColumnID() {
        return columnID;
    }

    public int getSyntax() {
        return syntax;
    }

    public MOAccess getAccess() {
        return access;
    }

    @SuppressWarnings("rawtypes")
    public MOTable getTable() {
        return table;
    }

    /**
     * Gets the value of the specified column from the provided row. The optional
     * {@code subRequest} parameter provides information on the currently processed
     * SNMP request if the value retrieval is trigger by a SNMP command.
     *
     * @param row
     *         the row with the value to be returned.
     * @param column
     *         the column index pointing to the column to return in the above row.
     * @param subRequest
     *         an optional sub-request on which behalf this value retrieval is executed.
     *
     * @return the value as a pointer to the cell value or {@code null} if such a value does not exist.
     * @since 2.6
     */
    @SuppressWarnings("unchecked")
    public V getValue(MOTableRow row, int column, SubRequest<?> subRequest) {
        return (V)row.getValue(column);
    }

    /**
     * Tests if the supplied row is volatile or persistent. If volatile then
     * the row will not be saved when the table is saved to persistent storage.
     *
     * @param row
     *         a row of the table where this column is part of.
     * @param column
     *         the column index of this column in {@code row}.
     *
     * @return {@code true} if {@code row} should not be
     */
    public boolean isVolatile(MOTableRow row, int column) {
        return false;
    }

    /**
     * Return the restore value for this column and the given row.
     *
     * @param rowValues
     *         a row of the table where this column is part of.
     * @param column
     *         the column index of this column in {@code row}.
     *
     * @return the restored value. By default this is {@code rowValues[column]}.
     * @since 2.4
     */
    public Variable getRestoreValue(Variable[] rowValues, int column) {
        return rowValues[column];
    }

    /**
     * Return the content of this column's value of the given row for persistent storage.
     *
     * @param row
     *         a row of the table where this column is part of.
     * @param column
     *         the column index of this column in {@code row}.
     *
     * @return the value to be stored persistently for this {@code row} and {@code column}.
     * @since 2.4
     */
    public Variable getStoreValue(MOTableRow row, int column) {
        return row.getValue(column);
    }

    /**
     * Compares this managed object column by its ID with another column.
     *
     * @param column
     *         another {@code MOColumn}.
     *
     * @return int
     * a negative integer, zero, or a positive integer as this column ID
     * is less than, equal to, or greater than the specified object's column
     * ID.
     */
    public int compareTo(MOColumn<V> column) {
        return columnID - column.getColumnID();
    }

    public String toString() {
        return this.getClass().getName() + "[columnID=" + getColumnID() + ",syntax=" +
                getSyntax() + "]";
    }

    /**
     * Process a get sub-request for the specified table row and column.
     *
     * @param subRequest
     *         the GET sub-request to execute.
     * @param row
     *         the row that contains the value to return in the GET response PDU.
     * @param column
     *         the column index of the value to return in {@code subRequest}
     */
    public void get(SubRequest<?> subRequest, MOTableRow row, int column) {
        if (getAccess().isAccessibleForRead()) {
            Variable value = getValue(row, column, subRequest);
            if (value != null) {
                subRequest.getVariableBinding().setVariable((Variable) value.clone());
            } else {
                subRequest.getVariableBinding().setVariable(Null.noSuchInstance);
            }
            subRequest.completed();
        } else {
            subRequest.getStatus().setErrorStatus(SnmpConstants.SNMP_ERROR_NO_ACCESS);
        }
    }

}
