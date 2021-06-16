/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DefaultMOTableRow.java  
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

import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.request.SnmpRequest;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.smi.*;
import java.util.Arrays;

/**
 * The {@code DefaultMOTableRow} is the default table row implementation.
 * Instances are compared by their index value.
 * The base row reference is not supported, since the default row implementation
 * is designed for read-only tables. For mutable rows, use instances
 * implementing the {@link MOMutableTableRow} interface.
 *
 * @author Frank Fock
 * @version 3.3.1
 */
public class DefaultMOTableRow implements MOTableRow, Comparable<MOTableRow> {

    protected Variable[] values;
    protected OID index;

    public DefaultMOTableRow(OID index, Variable[] values) {
        this.index = index;
        this.values = values;
    }

    public MOTableRow getBaseRow() {
        return null;
    }

    public OID getIndex() {
        return index;
    }

    public Variable getValue(int column) {
        return values[column];
    }

    public int size() {
        return values.length;
    }

    public boolean equals(Object obj) {
        if (obj instanceof MOTableRow) {
            MOTableRow other = (MOTableRow)obj;
            boolean equals = other.getIndex().equals(index);
            equals &= (size() == other.size());
            if (equals) {
                for (int i=0; (equals) && (i<size()); i++) {
                    Variable v1 = getValue(i);
                    Variable v2 = other.getValue(i);
                    equals = ((v1 == null) && (v2 == null)) ||
                            ((v1 != null) && (v1.equals(v2)));
                }
            }
            return equals;
        }
        return false;
    }

    public int hashCode() {
        return index.hashCode();
    }

    public String toString() {
        return "DefaultMOTableRow["+toStringMembers();
    }

    protected String toStringMembers() {
        return "index="+index+",values="+Arrays.asList(values);
    }

    public void setBaseRow(MOTableRow baseRow) {
    }

    /**
     * Compares this row with a {@link MOTableRow} instance
     * by their index values.
     * @param o
     *    a {@link MOTableRow} instance
     * @return
     *    {@code getIndex().compareTo(o.getIndex())}
     */
    public int compareTo(MOTableRow o) {
        return getIndex().compareTo(o.getIndex());
    }

    /**
     * Gets the value of the first column (if it exists) in the specified row and table that matches (equals) the given
     * column class.
     * It starts searching for the column from the first column and then proceeds last
     * until it finds it. If no matching column can be found, {@code null} is returned.
     * @param row
     *         a row with a {@link RowStatus} column (otherwise {@code null} is returned).
     * @param table
     *         the table of the given {@code row}.
     * @param columnClass
     *         the class of the column object.
     * @param subRequest
     *         an optional sub-request on which behalf this value retrieval is executed.
     * @return
     *         the value of the matched column in the given {@code row} or {@code null} if
     *         the table has no column with the specified column class.
     * @param <V>
     *           the value ({@link Variable}) class for this column.
     * @since 3.3.1
     */
    public static <V extends Variable> V getColumnValue(MOTableRow row, MOTable<?,?,?> table,
                                                        Class<MOColumn<V>> columnClass, SubRequest<?> subRequest) {
        int colID = 0;
        for (MOColumn<?> moColumn : table.getColumns()) {
            if (moColumn.getClass().equals(columnClass)) {
                return columnClass.cast(moColumn).getValue(row, colID, subRequest);
            }
            colID++;
        }
        return null;
    }
}
