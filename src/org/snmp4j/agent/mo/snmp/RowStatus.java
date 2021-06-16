/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - RowStatus.java  
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


package org.snmp4j.agent.mo.snmp;

import java.util.*;

import org.snmp4j.*;
import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.*;
import org.snmp4j.agent.request.*;
import org.snmp4j.smi.*;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;

/**
 * The {@code RowStatus} class implements the columnar object TC RowStatus.
 * The RowStatus textual convention is used to manage the creation and deletion
 * of conceptual rows, and is used as the value of the SYNTAX clause for the
 * status column of a conceptual row. See RFC 2579.
 * <p>
 * The RowStatus column controls row creation and deletion in SNMP tables with
 * READ-CREATE maximum access. Since the state of a dynamic row is/may be
 * important to dependent rows / other objects of an agent, row status change
 * events can be propagated to other objects through registering
 * {@link RowStatusListener}s.
 *
 * @param <R>
 *         The row type of the rows managed by this RowStatus.
 *
 * @author Frank Fock
 * @version 1.0
 */
public class RowStatus<R extends MOTableRow>
        extends MOMutableColumn<Integer32> implements MOChangeListener, MOTableRowListener<R> {

    private static final LogAdapter logger = LogFactory.getLogger(RowStatus.class);

    public static final int notExistent = 0;
    public static final int active = 1;
    public static final int notInService = 2;
    public static final int notReady = 3;
    public static final int createAndGo = 4;
    public static final int createAndWait = 5;
    public static final int destroy = 6;

    public enum RowStatusEnum {
        notExistent,
        active,
        notInService,
        notReady,
        createAndGo,
        createAndWait,
        destroy;

        public static RowStatusEnum fromValue(int rowStatusValue) {
            switch (rowStatusValue) {
                case RowStatus.notExistent:
                    return RowStatusEnum.notExistent;
                case RowStatus.active:
                    return RowStatusEnum.active;
                case RowStatus.notInService:
                    return RowStatusEnum.notInService;
                case RowStatus.notReady:
                    return RowStatusEnum.notReady;
                case RowStatus.createAndGo:
                    return RowStatusEnum.createAndGo;
                case RowStatus.createAndWait:
                    return RowStatusEnum.createAndWait;
                case RowStatus.destroy:
                    return RowStatusEnum.destroy;
            }
            return null;
        }
    }

    ;

    private OID oid;
    private int columnIndex;

    private transient List<RowStatusListener> rowStatusListeners;

    /**
     * Creates a RowStatus column with the specified column sub-identifier and
     * maximum access of 'read-create'.
     *
     * @param columnID
     *         a column sub-identifier.
     */
    public RowStatus(int columnID) {
        super(columnID, SMIConstants.SYNTAX_INTEGER,
                MOAccessImpl.ACCESS_READ_CREATE);
        this.addMOValueValidationListener(new RowStatusValidator());
    }

    /**
     * Creates a RowStatus column with the specified column sub-identifier.
     *
     * @param columnID
     *         a column sub-identifier.
     * @param access
     *         the maximum access for the RowStatus column (should be READ-CREATE).
     */
    public RowStatus(int columnID, MOAccess access) {
        super(columnID, SMIConstants.SYNTAX_INTEGER, access);
        this.addMOValueValidationListener(new RowStatusValidator());
    }

    /**
     * Sets the table instance this columnar object is contained in. This method
     * should be called by {@link MOTable} instance to register the table with
     * the RowStatus column. When called, this RowStatus registers itself as
     * {@link MOChangeListener} and {@link MOTableRowListener}.
     *
     * @param table
     *         the {@code MOTable} instance where this column is contained in.
     */
    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    public <R extends MOTableRow> void setTable(MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table) {
        super.setTable(table);
        oid = new OID(table.getOID());
        oid.append(getColumnID());
        columnIndex = table.getColumnIndex(getColumnID());

        table.addMOChangeListener(this);
        table.addMOTableRowListener((MOTableRowListener<R>) this);
    }

    /**
     * Unsets the table instance and thus unregisters itself as
     * {@link MOChangeListener} and {@link MOTableRowListener}.
     *
     * @param table
     *         the {@code MOTable} instance where this column was part of.
     */
    @SuppressWarnings("rawtypes")
    public void unsetTable(MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>> table) {
        columnIndex = 0;
        table.removeMOChangeListener(this);
        table.removeMOTableRowListener(this);
    }

    protected boolean isReady(MOTableRow row, int rowStatusColumn) {
        return isReady(row, rowStatusColumn, null);
    }

    protected boolean isReady(MOTableRow row, int rowStatusColumn, MOTableRow changeSet) {
        MOColumn<?>[] columns = getTable().getColumns();
        for (int i = 0; i < columns.length; i++) {
            if (i == rowStatusColumn) {
                continue;
            }
            if (columns[i] instanceof MOMutableColumn) {
                MOMutableColumn<?> mcol = (MOMutableColumn<?>) columns[i];
                if ((mcol.isMandatory()) &&
                        ((row.getValue(i) == null) &&
                                ((changeSet == null) || (changeSet.getValue(i) == null)))) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Row " + row + " is not ready because column " + i +
                                " is not set properly");
                    }
                    return false;
                }
            }
        }
        return true;
    }

    public void prepare(SubRequest<?> subRequest, MOTableRow row, MOTableRow changeSet, int column) {
        super.prepare(subRequest, row, null, column);
        if (subRequest.getStatus().getErrorStatus() == PDU.noError) {
            int newValue = ((Integer32) subRequest.getVariableBinding().getVariable()).getValue();
            int oldValue = notExistent;
            if (row.getValue(column) != null) {
                oldValue = ((Integer32) row.getValue(column)).getValue();
            }
            if ((oldValue == notExistent) || (oldValue == notReady) ||
                    (oldValue == createAndGo)) {
                switch (newValue) {
                    case createAndGo:
                    case notInService:
                    case active: {
                        if (!isReady(row, column, changeSet)) {
                            if (logger.isDebugEnabled()) {
                                logger.debug(toString() + ": Row '" +
                                        row.getIndex() +
                                        " is not ready! Cannot change status to from " +
                                        oldValue + " to " + newValue);
                            }
                            subRequest.getStatus().setErrorStatus(PDU.inconsistentValue);
                        }
                        break;
                    }
                }
            }
            RowStatusEvent rowStatusEvent = new RowStatusEvent(this, getTable(), row, changeSet,
                            oldValue, newValue, true, subRequest);
            fireRowStatusChanged(rowStatusEvent);
            if (rowStatusEvent.getDenyReason() != PDU.noError) {
                subRequest.getStatus().setErrorStatus(rowStatusEvent.getDenyReason());
            }
        }
    }

    public void commit(SubRequest<?> subRequest, MOTableRow row, MOTableRow changeSet, int column) {
        Variable change = changeSet.getValue(column);
        if (change == null) {
            // no actual change for the row status -> nothing to do
            subRequest.completed();
            return;
        }
        int newValue = change.toInt();
        if (row == null && newValue == destroy) {
            subRequest.completed();
            return;
        } else if (row == null) {
            subRequest.setErrorStatus(PDU.commitFailed);
            return;
        }
        int oldValue = row.getValue(column).toInt();
        super.commit(subRequest, row, null, column);
        if (!subRequest.hasError()) {
            assignNewValue(subRequest, row, column, newValue);
            RowStatusEvent rowStatusEvent =
                    new RowStatusEvent(this, getTable(), row, changeSet, oldValue, newValue, false, subRequest);
            fireRowStatusChanged(rowStatusEvent);
        }
    }

    protected void assignNewValue(SubRequest<?> subRequest, MOTableRow row, int column, int newValue) {
        switch (newValue) {
            case destroy: {
                if (row != null) {
                    MOTableRow deleted = getTable().removeRow(row.getIndex());
                    if (deleted != null) {
                        subRequest.setUndoValue(deleted);
                    }
                }
                break;
            }
            case createAndWait: {
                if (isReady(row, column)) {
                    ((Integer32) row.getValue(column)).setValue(RowStatus.notInService);
                } else {
                    ((Integer32) row.getValue(column)).setValue(RowStatus.notReady);
                }
                break;
            }
            case createAndGo: {
                ((Integer32) row.getValue(column)).setValue(RowStatus.active);
                break;
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void undo(SubRequest<?> subRequest, MOTableRow row, int column) {
        super.undo(subRequest, row, column);
        if (!subRequest.hasError()) {
            int newStatus = ((Integer32) row.getValue(column)).getValue();
            switch (newStatus) {
                case destroy: {
                    R oldRow = (R) subRequest.getUndoValue();
                    Integer32 oldValue = (Integer32) oldRow.getValue(column);
                    boolean added = getTable().addRow(oldRow);
                    if (!added) {
                        subRequest.getStatus().setErrorStatus(PDU.undoFailed);
                    } else {
                        RowStatusEvent rowStatusEvent =
                                new RowStatusEvent(this, getTable(), oldRow, row,
                                        oldValue.getValue(), RowStatus.destroy);
                        fireRowStatusChanged(rowStatusEvent);
                    }
                    break;
                }
                case createAndGo:
                case createAndWait: {
                    MOTableRow deleted = getTable().removeRow(row.getIndex());
                    if (deleted == null) {
                        subRequest.getStatus().setErrorStatus(PDU.undoFailed);
                    } else {
                        RowStatusEvent rowStatusEvent =
                                new RowStatusEvent(this, getTable(), row, deleted,
                                        RowStatus.notExistent, newStatus);
                        fireRowStatusChanged(rowStatusEvent);
                    }
                    break;
                }
            }
        }
    }

    public void beforePrepareMOChange(MOChangeEvent changeEvent) {
        if (changeEvent.getOID().startsWith(oid)) {
            int currentValue = notExistent;
            if (changeEvent.getOldValue() instanceof Integer32) {
                currentValue = ((Integer32) changeEvent.getOldValue()).getValue();
            }
            int newValue = ((Integer32) changeEvent.getNewValue()).getValue();
            if (newValue < RowStatus.active || newValue > RowStatus.destroy) {
                changeEvent.setDenyReason(PDU.wrongValue);
                return;
            }
            boolean ok = false;
            switch (currentValue) {
                case notExistent:
                    ok = ((newValue == createAndGo) ||
                            (newValue == createAndWait) || (newValue == destroy));
                    break;
                case notReady:
                    ok = ((newValue == destroy) || (newValue == active) ||
                            (newValue == notInService));
                    break;
                case active:
                    ok = ((newValue == active) ||
                            (newValue == notInService) || (newValue == destroy));
                    break;
                case notInService:
                    ok = ((newValue == notInService) ||
                            (newValue == active) || (newValue == destroy));
                    break;
                // for row creation
                case createAndWait:
                    ok = ((newValue == createAndWait) || (newValue == destroy));
                    break;
                case createAndGo:
                    ok = ((newValue == createAndGo) || (newValue == destroy));
                    break;
                case destroy:
                    ok = (newValue == destroy);
                    break;
            }
            if (!ok) {
                changeEvent.setDenyReason(PDU.inconsistentValue);
            }
        }
    }

    public void beforeMOChange(MOChangeEvent changeEvent) {
    }

    public void afterMOChange(MOChangeEvent changeEvent) {
    }

    public void afterPrepareMOChange(MOChangeEvent changeEvent) {
    }

    public synchronized void addRowStatusListener(RowStatusListener l) {
        List<RowStatusListener> listeners = rowStatusListeners;
        if (listeners == null) {
            listeners = new ArrayList<RowStatusListener>(2);
        } else {
            listeners = new ArrayList<RowStatusListener>(listeners);
        }
        listeners.add(l);
        rowStatusListeners = listeners;
    }

    public synchronized void removeRowStatusListener(RowStatusListener l) {
        List<RowStatusListener> listeners = rowStatusListeners;
        if (listeners != null) {
            listeners = new ArrayList<RowStatusListener>(listeners);
            listeners.remove(l);
            rowStatusListeners = listeners;
        }
    }

    protected void fireRowStatusChanged(RowStatusEvent event) {
        List<RowStatusListener> listeners = rowStatusListeners;
        if (listeners != null) {
            for (RowStatusListener listener : listeners) {
                listener.rowStatusChanged(event);
            }
        }
    }

    /**
     * Tests if the specified row is active.
     *
     * @param row
     *         a row with a RowStatus column.
     * @param rowStatusColumnIndex
     *         the column index of the RowStatus column in {@code row}.
     *
     * @return {@code true} if {@code row} is active.
     */
    public static boolean isRowActive(MOTableRow row, int rowStatusColumnIndex) {
        Integer32 rowStatus = (Integer32) row.getValue(rowStatusColumnIndex);
        return (rowStatus != null) && (rowStatus.getValue() == RowStatus.active);
    }

    /**
     * Gets the value of the RowStatus column (if it exists) in the specified row and table.
     * It starts searching for the {@link RowStatus} column from the last column and then proceeds down to the first
     * until it finds it. If no {@link RowStatus} column can be found, {@code null} is returned.
     * @param row
     *         a row with a {@link RowStatus} column (otherwise {@code null} is returned).
     * @param table
     *         the table of the given {@code row}.
     * @return
     *         the {@link Integer32} value of the {@link RowStatus} column in the given {@code row} or {@code null} if
     *         the table has no {@link RowStatus} column.
     * @since 3.3.0
     */
    public static Integer32 getRowStatus(MOTableRow row, MOTable<?,?,?> table) {
        int maxCol = table.getColumnCount();
        for (int c=maxCol-1; c >= 0; c--) {
            MOColumn<?> moColumn = table.getColumn(c);
            if (moColumn instanceof RowStatus) {
                Variable v = row.getValue(c);
                if (v == null) {
                    return new Integer32(RowStatus.notExistent);
                }
                return new Integer32(v.toInt());
            }
        }
        return null;
    }

    /**
     * The {@code ActiveRowsFilter} is a {@link MOTableRowFilter} that
     * returns only the active rows of a table with a RowStatus column.
     *
     * @author Frank Fock
     * @version 1.0
     */
    public static class ActiveRowsFilter<R extends MOTableRow> implements MOTableRowFilter<R> {

        private int rowStatusColumnIndex;

        /**
         * Creates an active row filter by specifying the RowStatus column's index
         * in the target table.
         *
         * @param rowStatusColumnIndex
         *         the column index (zero-based) of the RowStatus column on behalf the
         *         filtering is done.
         */
        public ActiveRowsFilter(int rowStatusColumnIndex) {
            this.rowStatusColumnIndex = rowStatusColumnIndex;
        }

        public boolean passesFilter(R row) {
            Integer32 rs = (Integer32) row.getValue(rowStatusColumnIndex);
            if (rs == null) {
                logger.warn("RowStatus column " + rowStatusColumnIndex +
                        " does not exists although it is filter criteria");
                return false;
            }
            return (rs.getValue() == active);
        }
    }

    /**
     * The {@code RowStatusFilter} is a {@link MOTableRowFilter} that
     * returns only those rows that have a status that equals one of those provided during creation of the filter.
     *
     * @author Frank Fock
     * @version 3.0
     * @since 3.0
     */
    public static class RowStatusFilter<R extends MOTableRow> implements MOTableRowFilter<R> {

        private int rowStatusColumnIndex;
        private Set<RowStatusEnum> passingStatusSet;

        public RowStatusFilter(int rowStatusColumnIndex, Set<RowStatusEnum> passingStatusSet) {
            this.rowStatusColumnIndex = rowStatusColumnIndex;
            this.passingStatusSet = passingStatusSet;
        }

        public boolean passesFilter(R row) {
            Integer32 rs = (Integer32) row.getValue(rowStatusColumnIndex);
            if (rs == null) {
                logger.warn("RowStatus column " + rowStatusColumnIndex +
                        " does not exists although it is filter criteria");
                return false;
            }
            RowStatusEnum rowStatusEnum = RowStatusEnum.fromValue(rs.getValue());
            return rowStatusEnum != null && (passingStatusSet.contains(rowStatusEnum));
        }

    }

    static class RowStatusValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent event) {
            if (!(event.getNewValue() instanceof Integer32)) {
                event.setValidationStatus(PDU.wrongType);
            }
            int v = ((Integer32) event.getNewValue()).getValue();
            if ((v < 1) || (v > 6) || (v == 3)) {
                event.setValidationStatus(PDU.wrongValue);
            }
        }
    }

    public void rowChanged(MOTableRowEvent<R> event) {
        switch (event.getType()) {
            case MOTableRowEvent.CREATE: {
                // by default do not allow row creation if RowStatus is not set!
                R row = event.getRow();
                int myIndex = getTable().getColumnIndex(getColumnID());
                if (row.getValue(myIndex) == null) {
                    event.setVetoStatus(PDU.inconsistentName);
                }
                break;
            }
            case MOTableRowEvent.CHANGE: {
                // check whether the changed column can be changed if row is active
                int rowStatus = getCurrentRowStatus(event);
                if (rowStatus == active) {
                    for (int i = 0; i < getTable().getColumnCount(); i++) {
                        if (event.getPreparedChanges().getValue(i) == null) {
                            continue;
                        }
                        MOColumn<?> col = getTable().getColumn(i);
                        if (col instanceof MOMutableColumn) {
                            if (!((MOMutableColumn<?>) col).isMutableInService()) {
                                event.setVetoStatus(PDU.inconsistentValue);
                                event.setVetoColumn(i);
                            }
                        }
                    }
                }
                break;
            }
            case MOTableRowEvent.UPDATED: {
                // check whether changed row is ready to be set active
                int rowStatus = getCurrentRowStatus(event);
                if (rowStatus == notReady) {
                    if ((event.getRow() instanceof MOMutableTableRow) &&
                            (isReady(event.getRow(), columnIndex))) {
                        ((MOMutableTableRow) event.getRow()).setValue(columnIndex, new Integer32(notInService));
                    }
                }
            }
        }
    }

    private int getCurrentRowStatus(MOTableRowEvent<R> event) {
        Integer32 rowStatusVariable = (Integer32) event.getRow().getValue(columnIndex);
        int rowStatus = RowStatus.notExistent;
        if (rowStatusVariable != null) {
            rowStatus = rowStatusVariable.getValue();
        }
        return rowStatus;
    }

    public boolean isVolatile(MOTableRow row, int column) {
        Integer32 value = (Integer32) row.getValue(column);
        if (value != null) {
            int rowStatus = value.getValue();
            if ((rowStatus != active) && (rowStatus != notInService)) {
                return true;
            }
        }
        return false;
    }

    public void get(SubRequest<?> subRequest, MOTableRow row, int column) {
        Integer32 rowStatus = getValue(row, column, subRequest);
        if ((rowStatus != null) && (rowStatus.getValue() == notReady)) {
            if (isReady(row, column)) {
                rowStatus.setValue(notInService);
            }
        }
        super.get(subRequest, row, column);
    }

}
