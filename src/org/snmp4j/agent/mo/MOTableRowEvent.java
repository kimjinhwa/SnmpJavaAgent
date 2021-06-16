/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOTableRowEvent.java  
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
import org.snmp4j.smi.Variable;

/**
 * The {@code MOTableRowEvent} class describes the changes
 *
 * @param <R>
 *         The {@link MOTable} row type of this event.
 *
 * @author Frank Fock
 * @version 3.3.0
 */
public class MOTableRowEvent<R extends MOTableRow> extends DeniableEventObject {

    private static final long serialVersionUID = 5846054060591503486L;

    /**
     * A single column of a row is changed.
     */
    public static final int CHANGE = 0;
    /**
     * A row is created.
     */
    public static final int CREATE = 1;
    /**
     * A row is added.
     */
    public static final int ADD = 2;
    /**
     * A row is deleted.
     */
    public static final int DELETE = 3;

    /**
     * This event type indicates that a complete row has been updated.
     */
    public static final int UPDATED = 4;

    /**
     * A row exists in the table at the moment when the corresponding {@link MOTableRowListener} has been added to the
     * table. Processing this event type can be used to create dependent rows in augmenting or otherwise extending
     * tables.
     *
     * @since 3.0
     */
    public static final int EXISTS = 5;

    @SuppressWarnings("rawtypes")
    private MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table;
    private R row;
    private MOTableRow preparedChanges;
    private int type;
    private int vetoColumn = -1;

    /**
     * Specifies the origin of a change: the source of an external change is a protocol operation (SNMP or AgentX)
     * that originates external to the managed object. The source of an internal change is originated from within the
     * managed object, for example when loading a row from persistent storage.
     * @since 3.3.0
     */
    public enum OriginType {
        /**
         * Change is originated from external source of the affected {@link org.snmp4j.agent.ManagedObject}, for example
         * by a SNMP (AgentX) protocol operation.
         */
        external,
        /**
         * Change is originated from internal source of the affected {@link org.snmp4j.agent.ManagedObject}, for example
         * by loading a row from persistent storage with {@link DefaultMOTable#loadRow(OID, Variable[], int)}.
         */
        internal
    };

    /**
     * Specifies the origin type of the change. Default is {@link OriginType#external}.
     * @since 3.3.0
     */
    private OriginType originType = OriginType.external;

    /**
     * The number of events that will follow from the same origin (and source trigger) if {@link
     * #sendNextEventsOfSameOrigin} is set to {@code true}.
     *
     * @since 3.0
     */
    private int numberOfConsecutiveEventsOfSameOrigin = 0;
    /**
     * Some events like {@link #EXISTS} are fired for more than one row at the same time. If the {@link
     * MOTableRowListener} is interested an all those events, then this attribute has to be set to true.
     *
     * @since 3.0
     */
    private boolean sendNextEventsOfSameOrigin = false;

    /**
     * Creates a table row event based on table, row and type that cannot be canceled by the event listener.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param type
     *         the event type.
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source, MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table, R row,
                           int type) {
        super(source, false);
        this.table = table;
        this.row = row;
        this.type = type;
    }

    /**
     * Creates a table row event based on table, row and type that cannot be canceled by the event listener.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param type
     *         the event type.
     * @param originType
     *         the origin type ({@link OriginType#external} or {@link OriginType#internal}) of this event.
     * @since 3.3.0
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source, MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table, R row,
                           int type, OriginType originType) {
        super(source, false);
        this.table = table;
        this.row = row;
        this.type = type;
        this.originType = originType;
    }

    /**
     * Creates a table row event based on table, row and type that may be canceled by the event listener depending on
     * the specified flag.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param type
     *         the event type.
     * @param deniable
     *         indicates whether the event can be canceled through setting its denyReason member to a SNMP error
     *         status.
     *
     * @since 1.1
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source, MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table, R row,
                           int type, boolean deniable) {
        super(source, deniable);
        this.table = table;
        this.row = row;
        this.type = type;
    }

    /**
     * Creates a table row event based on table, row and type that may be canceled by the event listener depending on
     * the specified flag.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param type
     *         the event type.
     * @param originType
     *         the origin type ({@link OriginType#external} or {@link OriginType#internal}) of this event.
     * @param deniable
     *         indicates whether the event can be canceled through setting its denyReason member to a SNMP error
     *         status.
     *
     * @since 3.3.0
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source, MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table, R row,
                           int type, OriginType originType,  boolean deniable) {
        super(source, deniable);
        this.table = table;
        this.row = row;
        this.type = type;
        this.originType = originType;
    }

    /**
     * Creates a table row event based on table, row, prepared changes, and type that cannot be canceled by the event
     * listener.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param preparedChanges
     *         a row instance containing the prepared changes for {@code row}.
     * @param type
     *         the event type.
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source,
                           MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table,
                           R row,
                           MOTableRow preparedChanges,
                           int type) {
        super(source, false);
        this.table = table;
        this.row = row;
        this.preparedChanges = preparedChanges;
        this.type = type;
    }

    /**
     * Creates a table row event based on table, row, prepared changes, and type that cannot be canceled by the event
     * listener. The {@link #originType} is set to {@link OriginType#internal} because this event cannot be originated
     * by external protocol operations.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param preparedChanges
     *         a row instance containing the prepared changes for {@code row}.
     * @param type
     *         the event type.
     * @param deniable
     *         indicates whether the event can be canceled through setting its denyReason member to a SNMP error
     *         status.
     * @param numberOfConsecutiveEventsOfSameOrigin
     *         specifies the total number of events that will are triggered by the same origin at once, for example the
     *         number of rows in a table with event type {@link #EXISTS}, when a listener is added to the table. The
     *         count is exclusive this event.
     *
     * @since 3.0
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source, MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table,
                           R row,
                           MOTableRow preparedChanges, int type, boolean deniable,
                           int numberOfConsecutiveEventsOfSameOrigin) {
        this(source, table, row, preparedChanges, type, deniable);
        this.numberOfConsecutiveEventsOfSameOrigin = numberOfConsecutiveEventsOfSameOrigin;
        this.originType = OriginType.internal;
    }

    /**
     * Creates a table row event based on table, row, prepared changes, and type.
     *
     * @param source
     *         the event source.
     * @param table
     *         the table.
     * @param row
     *         the row associated with this event.
     * @param preparedChanges
     *         a row instance containing the prepared changes for {@code row}.
     * @param type
     *         the event type.
     * @param deniable
     *         indicates whether the event can be canceled through setting its denyReason member to a SNMP error
     *         status.
     *
     * @since 1.1
     */
    @SuppressWarnings("rawtypes")
    public MOTableRowEvent(Object source,
                           MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table,
                           R row,
                           MOTableRow preparedChanges,
                           int type,
                           boolean deniable) {
        super(source, deniable);
        this.table = table;
        this.row = row;
        this.preparedChanges = preparedChanges;
        this.type = type;
    }

    public R getRow() {
        return row;
    }

    @SuppressWarnings("rawtypes")
    public MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> getTable() {
        return table;
    }

    public int getType() {
        return type;
    }

    /**
     * Returns the veto status that revokes the row operation or zero if the row operation is accepted by all
     * listeners.
     *
     * @return a SNMP or sub-agent protocol error status or zero if the row operation is accepted.
     */
    public int getVetoStatus() {
        return getDenyReason();
    }

    public MOTableRow getPreparedChanges() {
        return preparedChanges;
    }

    public int getVetoColumn() {
        return vetoColumn;
    }

    /**
     * Sets the veto status that revokes the row operation.
     *
     * @param denyReason
     *         a SNMP error status or a sub-agent protocol specific error status. In any case zero represents no error.
     */
    public void setVetoStatus(int denyReason) {
        setDenyReason(denyReason);
    }

    /**
     * Sets the column index on whose behalf the veto is issued.
     *
     * @param vetoColumn
     *         a column index.
     */
    public void setVetoColumn(int vetoColumn) {
        this.vetoColumn = vetoColumn;
    }

    public int getNumberOfConsecutiveEventsOfSameOrigin() {
        return numberOfConsecutiveEventsOfSameOrigin;
    }

    public boolean isSendNextEventsOfSameOrigin() {
        return sendNextEventsOfSameOrigin;
    }

    public void setSendNextEventsOfSameOrigin(boolean sendNextEventsOfSameOrigin) {
        this.sendNextEventsOfSameOrigin = sendNextEventsOfSameOrigin;
    }

    /**
     * Gets the {@link OriginType} of this event.
     * @return the origin type ({@link OriginType#external} or {@link OriginType#internal}) of this event.
     * @since 3.3.0
     */
    public OriginType getOriginType() {
        return originType;
    }

    public String toString() {
        return getClass().getName() + "[source=" + source + ",table=" + table + ",row=" + row +
                ",type=" + type + ",deniable=" + isDeniable() + ", originType="+originType +
                ",numberOfConsecutiveEventsOfSameOrigin=" + numberOfConsecutiveEventsOfSameOrigin +
                ",sendNextEventsOfSameOrigin=" + sendNextEventsOfSameOrigin + "]";
    }
}
