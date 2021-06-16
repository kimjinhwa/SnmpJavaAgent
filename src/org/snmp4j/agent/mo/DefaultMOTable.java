/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DefaultMOTable.java  
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

import org.snmp4j.PDU;
import org.snmp4j.agent.*;
import org.snmp4j.agent.io.*;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.request.Request;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.agent.util.OIDScope;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;
import java.util.*;

/**
 * The {@code DefaultMOTable} class is the default implementation of the {@link MOTable} class. For most use cases, it
 * is not necessary to customize this class through deriving your own sub-class. Instead, using a different {@link
 * MOTableModel} as table data provider is sufficient.
 * <p>
 * The default table model can be used to hold the data of a SNMP conceptual table as real tabular data. If you want to
 * implement a virtual table, you will have to directly implement the interfaces {@link MOTableModel} or {@link
 * MOMutableTableModel} to access the data based on the actual view.
 *
 * @author Frank Fock
 * @version 3.0
 */

@SuppressWarnings("rawtypes")
public class DefaultMOTable<R extends MOTableRow, C extends MOColumn, M extends MOTableModel<R>>
        implements MOTable<R, C, M>, MOScope,
        SerializableManagedObject<SubRequest<?>>, RandomAccessManagedObject<SubRequest<?>> {

    private static LogAdapter logger =
            LogFactory.getLogger(DefaultMOTable.class);

    private OID oid;
    private MOTableIndex indexDef;
    private C[] columns;
    protected M model;

    private boolean isVolatile;

    protected WeakHashMap<Request<?, ?, ?>, Map<OID, R>> newRows;
    protected WeakHashMap<Request<?, ?, ?>, Map<OID, ChangeSet>> pendingChanges;

    protected transient List<MOChangeListener> moChangeListeners;
    protected transient List<MOTableRowListener<R>> moTableRowListeners;

    private transient WeakHashMap<Request<?, ?, ?>, RowCacheEntry> walkCache;

    protected transient List<RowModificationControlColumn> rowModificationControlColumns;

    @SuppressWarnings("unchecked")
    private static Comparator columnComparator = (o1, o2) -> {
        int id1 = (o1 instanceof MOColumn) ?
                ((MOColumn) o1).getColumnID() : (Integer) o1;
        int id2 = (o2 instanceof MOColumn) ?
                ((MOColumn) o2).getColumnID() : (Integer) o2;
        return id1 - id2;
    };

    @SuppressWarnings("unchecked")
    public DefaultMOTable(OID oid, MOTableIndex indexDef, C[] columns) {
        this(oid, indexDef, columns, (M) new DefaultMOMutableTableModel<R>());
    }

    /**
     * Creates a new SNMP table with the specified "Entry" OID, INDEX, columns, and {@link MOTableModel}.
     *
     * @param oid
     *         the OID of the SNMP table's Entry object. If the table is ifTable (1.3.6.1.2.1.2.2) then the OID to
     *         provide is  1.3.6.1.2.1.2.2.1 which is the ifEntry OID. By SMI rule, you can simply append ".1" to the
     *         table OID.
     * @param indexDef
     *         the index definition of the table based on the INDEX clause of the table MIB definition.
     * @param columns
     *         the column definitions which may also include non-accessible columns.
     * @param model
     *         the table model holding the table data.
     */
    public DefaultMOTable(OID oid, MOTableIndex indexDef, C[] columns, M model) {
        this.oid = oid;
        this.indexDef = indexDef;
        this.columns = columns;
        this.model = model;
        registerColumns();
    }

    @SuppressWarnings("unchecked")
    private void registerColumns() {
        for (C column : columns) {
            column.setTable(this);
        }
    }

    public MOTableCellInfo getCellInfo(OID oid) {
        return new CellInfo(this, oid);
    }

    @SuppressWarnings("unchecked")
    public int getColumnIndex(int id) {
        return Arrays.binarySearch(columns, id, columnComparator);
    }

    public C getColumn(int index) {
        return columns[index];
    }

    public int getColumnCount() {
        return columns.length;
    }

    /**
     * Creates a new row for this table with the supplied index and initial values. If the underlying table model is not
     * a {@link MOMutableTableModel} instance or if one of the {@link MOTableRowListener} deny the row creation attempt
     * then {@code null} will be returned.
     *
     * @param index
     *         the index OID of the new row.
     * @param initialValues
     *         the initial values that should be assigned to the new row. If the array contains less values than this
     *         table has columns, default values will be created for the missing columns.
     *
     * @return the created {@code MOTableRow} instance or {@code null} if the row cannot be created.
     */
    @SuppressWarnings("unchecked")
    public R createRow(OID index, Variable[] initialValues) {
        return createRowInternal(index, initialValues, MOTableRowEvent.OriginType.external);
    }

    /**
     * Creates a new row for this table with the supplied index and initial values. If the underlying table model is not
     * a {@link MOMutableTableModel} instance or if one of the {@link MOTableRowListener} deny the row creation attempt
     * then {@code null} will be returned.
     * The {@link org.snmp4j.agent.mo.MOTableRowEvent.OriginType} specifies whether this method is called on behalf
     * of an external SNMP (AgentX) protocol operation or behalf of an internal load operation.
     *
     * @param index
     *         the index OID of the new row.
     * @param initialValues
     *         the initial values that should be assigned to the new row. If the array contains less values than this
     *         table has columns, default values will be created for the missing columns.
     * @param originType
     *         the origin type ({@link MOTableRowEvent.OriginType#external} or {@link MOTableRowEvent.OriginType#internal})
     *         of this event.
     *
     * @return the created {@code MOTableRow} instance or {@code null} if the row cannot be created.
     * @since 3.3.0
     */
    @SuppressWarnings("unchecked")
    public R createRowInternal(OID index, Variable[] initialValues, MOTableRowEvent.OriginType originType) {
        if (model instanceof MOMutableTableModel) {
            Variable[] values = initialValues;
            if (values.length < getColumnCount()) {
                values = getDefaultValues();
                System.arraycopy(initialValues, 0, values, 0, initialValues.length);
            }
            R row = ((MOMutableTableModel<R>) model).createRow(index, values);
            MOTableRowEvent<R> rowEvent =
                    new MOTableRowEvent<R>(this, this, row, MOTableRowEvent.CREATE, originType, true);
            fireRowChanged(rowEvent);
            if (rowEvent.getVetoStatus() == SnmpConstants.SNMP_ERROR_SUCCESS) {
                return row;
            }
        }
        return null;
    }


    @Override
    public R addNewRow(OID index, Variable[] initialValues) {
        R newRow = createRow(index, initialValues);
        if (newRow != null) {
            addRow(newRow);
        }
        return newRow;
    }

    public R createRow(OID index) {
        return createRow(index, getDefaultValues());
    }

    /**
     * Adds the supplied row to the underlying table model and fires the appropriate {@link MOTableRowEvent}. Since this
     * method is typically called during the commit phase of a SET request that creates a table, it should be avoided to
     * return an error here. Instead, error checking should be placed in the {@link #prepare} method. The {@link
     * org.snmp4j.agent.mo.MOTableRowEvent.OriginType} of the fired {@link MOTableRowEvent} is set to {@link
     * org.snmp4j.agent.mo.MOTableRowEvent.OriginType#external}.
     *
     * @param row
     *         the {@code MOTableRow} to add.
     *
     * @return {@code true} if the row has been added or {@code false} if it could not be added.
     */
    @SuppressWarnings("unchecked")
    public boolean addRow(R row) {
        return addRowInternal(row, MOTableRowEvent.OriginType.external);
    }

    /**
     * Adds the supplied row to the underlying table model and fires the appropriate {@link MOTableRowEvent}.
     * The {@link org.snmp4j.agent.mo.MOTableRowEvent.OriginType} specifies whether this method is called on behalf
     * of an external SNMP (AgentX) protocol operation or behalf of an internal load operation.
     *
     * @param row
     *         the {@code MOTableRow} to add.
     * @param originType
     *         the origin type ({@link MOTableRowEvent.OriginType#external} or {@link MOTableRowEvent.OriginType#internal})
     *         of this event.
     *
     * @return {@code true} if the row has been added or {@code false} if it could not be added.
     */
    @SuppressWarnings("unchecked")
    protected boolean addRowInternal(R row, MOTableRowEvent.OriginType originType) {
        if (model instanceof MOMutableTableModel) {
            MOTableRowEvent<R> rowEvent =
                    new MOTableRowEvent<R>(this, this, row, MOTableRowEvent.ADD, originType, true);
            fireRowChanged(rowEvent);
            if (rowEvent.getVetoStatus() == SnmpConstants.SNMP_ERROR_SUCCESS) {
                ((MOMutableTableModel<R>) model).addRow(row);
                MOChangeEvent moChangeEvent =
                        new MOChangeEvent(this, this, row.getIndex(), MOChangeEvent.Modification.added);
                fireAfterMOChange(moChangeEvent);
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public R removeRow(OID index) {
        if (model instanceof MOMutableTableModel) {
            R row = model.getRow(index);
            if (row == null) {
                return null;
            }
            MOTableRowEvent<R> rowEvent =
                    new MOTableRowEvent<R>(this, this, row, MOTableRowEvent.DELETE, true);
            fireRowChanged(rowEvent);
            if (rowEvent.getVetoStatus() == SnmpConstants.SNMP_ERROR_SUCCESS) {
                R removedRow = ((MOMutableTableModel<R>) model).removeRow(index);
                MOChangeEvent changeEvent =
                        new MOChangeEvent(this, this, index, MOChangeEvent.Modification.removed);
                fireAfterMOChange(changeEvent);
                return (removedRow != null) ? removedRow : row;
            }
        }
        return null;
    }

    /**
     * Removes all rows from this table. Before a row is removed the corresponding DELETE event is fired and listeners
     * may veto these events for all rows. Only if there is no veto, a row will be deleted. The number of deleted rows
     * is then returned.
     *
     * @return the number of removed rows or -1 if the table model does not support row removal.
     */
    public int removeAll() {
        int count = 0;
        if (model instanceof MOMutableTableModel) {
            while (model.getRowCount() > 0) {
                R row = model.firstRow();
                if (row != null) {
                    MOTableRowEvent<R> rowEvent =
                            new MOTableRowEvent<R>(this, this, row, MOTableRowEvent.DELETE, true);
                    fireRowChanged(rowEvent);
                    if (rowEvent.getVetoStatus() == SnmpConstants.SNMP_ERROR_SUCCESS) {
                        ((MOMutableTableModel) model).removeRow(row.getIndex());
                        MOChangeEvent changeEvent =
                                new MOChangeEvent(this, this, row.getIndex(), MOChangeEvent.Modification.removed);
                        fireAfterMOChange(changeEvent);
                    }
                    count++;
                }
            }
        } else {
            count = -1;
        }
        return count;
    }

    /**
     * Remove all rows that have a {@link StorageType} column with a value that matches one of the provided values.
     *
     * @param storageTypeSet
     *         a set of {@link org.snmp4j.agent.mo.snmp.StorageType.StorageTypeEnum} values.
     *
     * @return the number of deleted rows or -1 if the table does not contain a {@link StorageType} column.
     * @since 3.0
     */
    public int removeAnyStorageType(Set<StorageType.StorageTypeEnum> storageTypeSet) {
        int storageTypeCol = 0;
        for (C column : columns) {
            if (column instanceof StorageType) {
                break;
            }
            storageTypeCol++;
        }
        if (storageTypeCol >= columns.length) {
            return -1;
        }
        return removeAnyStorageType(storageTypeSet, storageTypeCol);
    }

    @SuppressWarnings("unchecked")
    protected int removeAnyStorageType(Set<StorageType.StorageTypeEnum> storageTypeSet, int storageTypeColumn) {
        if (storageTypeColumn < 0 || storageTypeColumn >= columns.length) {
            return -1;
        }
        int count = 0;
        MOTableRowFilter<R> storageTypeRowFilter = new MOTableRowFilter<R>() {
            @Override
            public boolean passesFilter(R row) {
                Variable storageType = row.getValue(storageTypeColumn);
                StorageType.StorageTypeEnum storageTypeEnum = StorageType.StorageTypeEnum.fromValue(storageType.toInt());
                return (storageTypeEnum == null || !storageTypeSet.contains(storageTypeEnum));
            }
        };
        if (model instanceof MOMutableTableModel) {
            List<MOTableRow> deletedRows = ((MOMutableTableModel) model).clear(storageTypeRowFilter);
            count = deletedRows.size();
        } else {
            count = -1;
        }
        return count;

    }

    public void commit(SubRequest<?> request) {
        OID cellOID = request.getVariableBinding().getOid();
        MOTableCellInfo cell = getCellInfo(cellOID);
        MOMutableColumn<?> col = (MOMutableColumn) getColumn(cell.getColumn());
        if (logger.isDebugEnabled()) {
            logger.debug("Committing sub-request (" +
                    request.getVariableBinding() + ") for column: " + col);
        }
        // Make sure changes are atomic -> sync whole table model
        synchronized (model) {
            R row = null;
            if (hasNewRows(request.getRequest())) {
                row = getNewRows(request.getRequest()).get(cell.getIndex());
                // check if row has been added already
                if ((row != null) && (!model.containsRow(row.getIndex()))) {
                    if (!addRow(row)) {
                        request.setErrorStatus(PDU.resourceUnavailable);
                        return;
                    }
                }
            }
            if (row == null) {
                row = model.getRow(cell.getIndex());
            }
            Variable oldValue = null;
            if ((row != null) && (moChangeListeners != null)) {
                oldValue = row.getValue(cell.getColumn());
                MOChangeEvent changeEvent =
                        new MOChangeEvent(this, new CellProxy(cell),
                                cell.getCellOID(),
                                oldValue,
                                request.getVariableBinding().getVariable(),
                                false, request);
                fireBeforeMOChange(changeEvent);
            }
            ChangeSet changeSet = getPendingChangeSet(request, cell.getIndex());
            // commit
            col.commit(request, row, changeSet, cell.getColumn());
            boolean isChangeSetComplete = isChangeSetComplete(request, cell.getIndex(), cell.getColumn());
            if (moChangeListeners != null) {
                MOChangeEvent changeEvent =
                        new MOChangeEvent(this, new CellProxy(cell),
                                cell.getCellOID(),
                                oldValue,
                                request.getVariableBinding().getVariable(),
                                false, request);
                fireAfterMOChange(changeEvent);
            }
            if (row != null && isChangeSetComplete) {
                if (row instanceof MOMutableRow2PC) {
                    @SuppressWarnings("unchecked")
                    MOMutableRow2PC<SubRequest<?>> mutableRow2PC = (MOMutableRow2PC<SubRequest<?>>) row;
                    mutableRow2PC.commitRow(request, changeSet);
                }
                if (model.containsRow(row.getIndex())) {
                    if (moChangeListeners != null) {
                        MOChangeEvent moChangeEvent =
                                new MOChangeEvent(this, this, row.getIndex(),
                                        MOChangeEvent.Modification.updated, request);
                        fireAfterMOChange(moChangeEvent);
                    }
                    if (moTableRowListeners != null) {
                        MOTableRowEvent<R> rowEvent =
                                new MOTableRowEvent<R>(this, this, row, MOTableRowEvent.UPDATED);
                        fireRowChanged(rowEvent);
                    }
                }
            }
        }
    }

    public final OID getIndexPart(OID anyOID) {
        int offset = oid.size() + 1;
        if ((anyOID.size() <= offset) || (!anyOID.startsWith(oid))) {
            return null;
        }
        return new OID(anyOID.getValue(), offset, anyOID.size() - offset);
    }

    public OID getCellOID(OID index, int col) {
        OID retval = new OID(oid);
        retval.append(columns[col].getColumnID());
        retval.append(index);
        return retval;
    }

    private MOTableCellInfo getNextCell(int col,
                                        OID indexLowerBound,
                                        boolean isLowerBoundIncluded) {
        for (int i = col; i < columns.length; i++) {
            Iterator<R> it = model.tailIterator(indexLowerBound);
            if (!it.hasNext()) {
                if (indexLowerBound == null) {
                    return null;
                }
                indexLowerBound = null;
                isLowerBoundIncluded = true;
            } else {
                if ((indexLowerBound != null) && (!isLowerBoundIncluded)) {
                    MOTableRow row = it.next();
                    if (row.getIndex().compareTo(indexLowerBound) > 0) {
                        // the specified index does not exists so we can use this next one:
                        return new CellInfo(this, row.getIndex(), i, columns[i].getColumnID(),
                                row);
                    }
                }
                indexLowerBound = null;
                isLowerBoundIncluded = true;
                if (it.hasNext()) {
                    MOTableRow row = it.next();
                    if (row == null) {
                        continue;
                    }
                    return new CellInfo(this, row.getIndex(), i, columns[i].getColumnID(), row);
                }
            }
        }
        return null;
    }

    public OID find(MOScope range) {
        MOTableCellInfo cellInfo = findCell(range, null);
        if (cellInfo != null) {
            return cellInfo.getCellOID();
        }
        return null;
    }

    protected MOTableCellInfo findCell(MOScope range, SubRequest<?> request) {
        synchronized (model) {
            update(range, request);
            // determine column
            if (model.isEmpty()) {
                return null;
            }
            MOTableCellInfo cellInfo = getCellInfo(range.getLowerBound());
            int col = cellInfo.getColumn();
            boolean exactMatch = true;
            if (col < 0) {
                col = (-col) - 1;
                exactMatch = false;
            }
            if (col >= columns.length) {
                return null;
            }
            boolean lowerIncluded = (!exactMatch) || range.isLowerIncluded();
            RowCacheEntry rowEntry = null;
            if (request != null) {
                rowEntry = getWalkCacheEntry(request, cellInfo, lowerIncluded);
            }
            MOTableCellInfo next;
            if (rowEntry != null) {
                next = new CellInfo(this, rowEntry.row.getIndex(),
                        col, cellInfo.getColumnID(), rowEntry.row);
            } else {
                next = getNextCell(col, cellInfo.getIndex(), lowerIncluded);
                if ((request != null) && (next != null) && (next.getColumn() == col)) {
                    addWalkCacheEntry(request, cellInfo.getIndex(), lowerIncluded,
                            ((CellInfo) next).row);
                }
            }
            if (next != null) {
                OID cellOID = next.getCellOID();
                if (range.isCovered(new OIDScope(cellOID))) {
                    return next;
                }
            }
        }
        return null;
    }

    private void addWalkCacheEntry(SubRequest<?> request, OID lowerBound, boolean lowerIncluded, MOTableRow row) {
        if (walkCache == null) {
            walkCache = new WeakHashMap<>(4);
        }
        walkCache.put(request.getRequest(),
                new RowCacheEntry(row, lowerBound, lowerIncluded));
    }

    private RowCacheEntry getWalkCacheEntry(SubRequest<?> request, MOTableCellInfo cellInfo, boolean lowerIncluded) {
        if (walkCache != null) {
            RowCacheEntry entry = walkCache.get(request.getRequest());
            if (entry == null) {
                return null;
            }
            if (((entry.searchLowerBound == null) && (cellInfo.getIndex() == null)) ||
                    ((entry.searchLowerBound != null) &&
                            (entry.searchLowerBound.equals(cellInfo.getIndex())) &&
                            (lowerIncluded == entry.searchLowerBoundIncluded))) {
                return entry;
            }
        }
        return null;
    }

    public MOScope getScope() {
        return this;
    }

    @Override
    public Variable getValue(OID cellOID) {
        MOTableCellInfo cell = getCellInfo(cellOID);
        if ((cell.getIndex() != null) &&
                (cell.getColumn() >= 0) && (cell.getColumn() < columns.length)) {
            return getValue(cell.getIndex(), cell.getColumn());
        }
        return null;
    }

    public Variable getValue(OID index, int col, SubRequest<?> req) {
        MOTableRow row = model.getRow(index);
        return getValue(row, col, req);
    }

    @Override
    public Variable getValue(OID index, int col) {
        MOTableRow row = model.getRow(index);
        return getValue(row, col, null);
    }

    @SuppressWarnings("unchecked")
    protected Variable getValue(MOTableRow row, int col, SubRequest<?> req) {
        if ((row != null) && (col >= 0) && (col < row.size())) {
            return columns[col].getValue(row, col, req);
        }
        return null;
    }

    /**
     * Update the content of this table that is covered by the supplied scope.
     * <p>
     * This method is part of the {@link UpdatableManagedObject} interface. Although the {@link DefaultMOTable} does not
     * implement that interface, subclasses of this class may do so easily by overriding this hook-up method.
     *
     * @param updateScope
     *         the scope to update. If {@code null} the whole managed object is updated.
     *
     * @see #update(MOScope range, SubRequest request)
     * @since 1.2
     */
    public void update(MOScope updateScope) {
        // nothing to do by default -> overwrite to update an updatable table.
    }

    /**
     * Update this table for the supplied search range and sub-request if it has not yet been updated for that request.
     * <p>
     * By default, the {@link #update(MOScope updateScope)} is being called on behalf of this method call (which itself
     * does not nothing by default). You may choose either to implement the {@link UpdatableManagedObject} interface and
     * implement its interface in a subclass. Then it is recommended to overwrite this method by an empty method.
     * Otherwise, do not implement the {@link UpdatableManagedObject} interface.
     * </p>
     *
     * @param range
     *         the search range.
     * @param request
     *         the sub-request triggered the update or {@code null} if that request cannot be determined.
     */
    protected void update(MOScope range, SubRequest<?> request) {
        Object updateMarker = null;
        if ((request != null) && (request.getRequest() != null)) {
            updateMarker = request.getRequest().getProcessingUserObject(getOID());
        }
        if (updateMarker == null) {
            if ((request != null) && (request.getRequest() != null)) {
                request.getRequest().setProcessingUserObject(getOID(), new Object());
            }
            update(range);
        }
    }

    @Override
    public void get(SubRequest<?> request) {
        OID cellOID = request.getVariableBinding().getOid();
        MOTableCellInfo cell = getCellInfo(cellOID);
        if ((cell.getIndex() != null) &&
                (cell.getColumn() >= 0) && (cell.getColumn() < columns.length)) {
            // update the table part affected by this query
            update(request.getScope(), request);

            MOColumn<?> col = getColumn(cell.getColumn());
            MOTableRow row = model.getRow(cell.getIndex());
            if (row == null) {
                request.getVariableBinding().setVariable(Null.noSuchInstance);
            } else if (col != null) {
                col.get(request, row, cell.getColumn());
            } else {
                request.getStatus().setErrorStatus(PDU.noAccess);
            }
        } else {
            if (cell.getColumn() >= 0) {
                request.getVariableBinding().setVariable(Null.noSuchInstance);
            } else {
                request.getVariableBinding().setVariable(Null.noSuchObject);
            }
        }
        request.completed();
    }

    @Override
    public boolean next(SubRequest<?> request) {
        DefaultMOScope scope = new DefaultMOScope(request.getScope());
        MOTableCellInfo nextCell;
        while ((nextCell = findCell(scope, request)) != null) {
            if (columns[nextCell.getColumn()].getAccess().isAccessibleForRead()) {
                Variable value;
                // Use row instance from cell info as shortcut if available
                if ((nextCell instanceof CellInfo) &&
                        (((CellInfo) nextCell).getRow() != null)) {
                    value = getValue(((CellInfo) nextCell).getRow(), nextCell.getColumn(), request);
                } else {
                    value = getValue(nextCell.getIndex(), nextCell.getColumn(), request);
                }
                if (value == null) {
                    scope.setLowerBound(nextCell.getCellOID());
                    scope.setLowerIncluded(false);
                } else {
                    request.getVariableBinding().setOid(nextCell.getCellOID());
                    request.getVariableBinding().setVariable(value);
                    request.completed();
                    return true;
                }
            } else {
                if (nextCell.getColumn() + 1 < getColumnCount()) {
                    OID nextColOID = new OID(getOID());
                    nextColOID.append(columns[nextCell.getColumn() + 1].getColumnID());
                    scope.setLowerBound(nextColOID);
                    scope.setLowerIncluded(false);
                } else {
                    return false;
                }
            }
        }
        return false;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void prepare(SubRequest<?> request) {
        OID cellOID = request.getVariableBinding().getOid();
        MOTableCellInfo cell = getCellInfo(cellOID);
        if (cell.getIndex() == null) {
            request.getStatus().setErrorStatus(PDU.inconsistentName);
            return;
        }
        if ((cell.getColumn() >= 0) && (cell.getColumn() < columns.length)) {
            MOColumn<?> col = getColumn(cell.getColumn());
            if (logger.isDebugEnabled()) {
                logger.debug("Preparing sub-request (" + request.getVariableBinding() + ")" +
                        " for column: " + col);
            }
            if ((col instanceof MOMutableColumn) && (col.getAccess().isAccessibleForWrite())) {
                MOMutableColumn<?> mcol = (MOMutableColumn) col;
                // check index
                if (getIndexDef().isValidIndex(cell.getIndex())) {
                    R row = model.getRow(cell.getIndex());
                    boolean newRow = false;
                    if (row == null) {
                        // look for already prepared row
                        row = getNewRows(request.getRequest()).get(cell.getIndex());
                        newRow = true;
                    }
                    if (row != null) {
                        prepare(request, cell, mcol, row, newRow);
                        request.completed();
                    } else if (model instanceof MOMutableTableModel) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Trying to create new row '" + cell.getIndex() + "'");
                        }
                        MOMutableTableModel<R> mmodel = (MOMutableTableModel<R>) model;
                        // create new row
                        try {
                            row = createRow(request, cell, mmodel);
                            if (row == null) {
                                request.getStatus().setErrorStatus(PDU.noCreation);
                            } else {
                                prepare(request, cell, mcol, row, true);
                                request.completed();
                            }
                        } catch (UnsupportedOperationException ex) {
                            request.getStatus().setErrorStatus(PDU.noCreation);
                        }
                    } else {
                        request.getStatus().setErrorStatus(PDU.noCreation);
                    }
                } else {
                    // invalid index
                    if (logger.isDebugEnabled()) {
                        logger.debug("Invalid index '" + cell.getIndex() +
                                "' for row creation in table " + getID());
                    }
                    request.getStatus().setErrorStatus(PDU.noCreation);
                }
            } else {
                // read-only column
                request.getStatus().setErrorStatus(PDU.notWritable);
            }
        } else {
            request.getStatus().setErrorStatus(PDU.noCreation);
        }
    }

    protected synchronized List<RowModificationControlColumn> getRowModificationControlColumns() {
        if (this.rowModificationControlColumns == null) {
            this.rowModificationControlColumns = new ArrayList<>(2);
            for (C column : getColumns()) {
                if (column instanceof RowModificationControlColumn) {
                    this.rowModificationControlColumns.add((RowModificationControlColumn) column);
                }
            }
        }
        return this.rowModificationControlColumns;
    }

    private R createRow(SubRequest<?> request, MOTableCellInfo cell, MOMutableTableModel<R> mmodel)
            throws UnsupportedOperationException {
        MOColumn<?> col = getColumn(cell.getColumn());
        if (!col.getAccess().isAccessibleForCreate()) {
            // creation not allowed
            return null;
        }
        Variable[] initialValues = new Variable[getColumnCount()];
        getChangesFromRequest(cell.getIndex(), null, request,
                initialValues, true, true);
        R row = mmodel.createRow(cell.getIndex(), initialValues);
        getNewRows(request.getRequest()).put(row.getIndex(), row);
        return row;
    }

    private void prepare(SubRequest<?> request, MOTableCellInfo cell, MOMutableColumn<?> mcol, R row, boolean creation) {
        if (moChangeListeners != null) {
            MOChangeEvent changeEvent =
                    new MOChangeEvent(this, new CellProxy(cell),
                            cell.getCellOID(),
                            (creation) ? null : row.getValue(cell.getColumn()),
                            request.getVariableBinding().getVariable(),
                            true, request);
            fireBeforePrepareMOChange(changeEvent);
            if (changeEvent.getDenyReason() != PDU.noError) {
                request.getStatus().setErrorStatus(changeEvent.getDenyReason());
            }
        }
        ChangeSet changeSet = getPendingChangeSet(request, cell.getIndex());
        if (changeSet == null) {
            changeSet = addPendingChanges(request, row, creation);
        }
        if ((moTableRowListeners != null) && (!request.hasError())) {
            if (isChangeSetComplete(request, row.getIndex(), cell.getColumn())) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Change set complete column=" + cell.getColumn() + ",rowIndex=" +
                            row.getIndex() + ",request=" + request);
                }
                MOTableRowEvent<R> rowEvent =
                        new MOTableRowEvent<R>(this, this, row, changeSet, (creation) ?
                                MOTableRowEvent.CREATE : MOTableRowEvent.CHANGE,
                                true);
                fireRowChanged(rowEvent);
                if (rowEvent.getVetoStatus() != PDU.noError) {
                    if (rowEvent.getVetoColumn() >= 0) {
                        int colID = columns[rowEvent.getVetoColumn()].getColumnID();
                        OID prefix = new OID(getOID());
                        prefix.append(colID);
                        SubRequest<?> r = request.getRequest().find(prefix);
                        if (r != null) {
                            r.getStatus().setErrorStatus(rowEvent.getVetoStatus());
                        } else {
                            request.getRequest().setErrorStatus(rowEvent.getVetoStatus());
                        }
                    } else {
                        request.getRequest().setErrorStatus(rowEvent.getVetoStatus());
                    }
                }
            } else if (logger.isDebugEnabled()) {
                logger.debug("Change set not yet complete on column=" + cell.getColumn() +
                        ",rowIndex=" + row.getIndex() +
                        ",request=" + request);
            }
        }
        if (request.getStatus().getErrorStatus() == PDU.noError) {
            mcol.prepare(request, row, changeSet, cell.getColumn());
            MOChangeEvent changeEvent =
                    new MOChangeEvent(this, new CellProxy(cell),
                            cell.getCellOID(),
                            row.getValue(cell.getColumn()),
                            request.getVariableBinding().getVariable(),
                            true, request);
            fireAfterPrepareMOChange(changeEvent);
            if (changeEvent.getDenyReason() != PDU.noError) {
                request.getStatus().setErrorStatus(changeEvent.getDenyReason());
            } else if (isChangeSetComplete(request, row.getIndex(), cell.getColumn())) {
                if (row instanceof MOMutableTableRow) {
                    List<RowModificationControlColumn> modificationControlColumns = getRowModificationControlColumns();
                    if (modificationControlColumns != null && modificationControlColumns.size() > 0) {
                        for (RowModificationControlColumn controlColumn : modificationControlColumns) {
                            controlColumn.prepareRow(request, (MOMutableTableRow) row, changeSet);
                        }
                    }
                }
                if (!request.hasError() && (row instanceof MOMutableRow2PC)) {
                    @SuppressWarnings("unchecked")
                    MOMutableRow2PC<SubRequest<?>> mutableRow2PC = (MOMutableRow2PC<SubRequest<?>>) row;
                    mutableRow2PC.prepareRow(request, changeSet);
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected int getChangesFromRequest(OID index, MOTableRow row, SubRequest<?> request, Variable[] values,
                                        boolean setDefaultValues, boolean newRow) {
        int lastChangedColumn = -1;
        // assign default values
        if (setDefaultValues) {
            for (int i = 0; (i < values.length) && (i < getColumnCount()); i++) {
                if (columns[i] instanceof MOMutableColumn) {
                    values[i] = ((MOMutableColumn) columns[i]).getDefaultValue();
                }
            }
        }
        Request<?, ?, ? extends SubRequest<?>> req = request.getRequest();
        for (Iterator<? extends SubRequest<?>> it = req.iterator(); it.hasNext(); ) {
            SubRequest<?> sreq = it.next();
            OID id = sreq.getVariableBinding().getOid();
            MOTableCellInfo cellInfo = getCellInfo(id);
            if (index.equals(cellInfo.getIndex())) {
                int col = cellInfo.getColumn();
                if ((col >= 0) && (col < values.length)) {
                    Variable v = sreq.getVariableBinding().getVariable();
                    // check that value is really changed
                    if ((v != null) &&
                            ((row == null) || (newRow) ||
                                    (row.size() <= col) ||
                                    (!v.equals(row.getValue(col))))) {
                        values[col] = v;
                        lastChangedColumn = col;
                    }
                }
            }
        }
        return lastChangedColumn;
    }

    protected boolean hasNewRows(Request<?, ?, ?> key) {
        return ((newRows != null) && (newRows.get(key) != null));
    }

    protected Map<OID, R> getNewRows(Request<?, ?, ?> key) {
        if (newRows == null) {
            newRows = new WeakHashMap<>(4);
        }
        return newRows.computeIfAbsent(key, k -> new HashMap<>(5));
    }

    protected synchronized boolean isChangeSetComplete(SubRequest<?> subRequest, OID index, int column) {
        ChangeSet changeSet = getPendingChangeSet(subRequest, index);
        return (changeSet == null) || (changeSet.getLastChangedColumn() == column);
    }

    protected synchronized ChangeSet addPendingChanges(SubRequest<?> subRequest, MOTableRow row, boolean newRow) {
        if (pendingChanges == null) {
            pendingChanges = new WeakHashMap<>(4);
        }
        Map<OID, ChangeSet> rowMap =
                pendingChanges.computeIfAbsent(subRequest.getRequest(), k -> new HashMap<>(5));
        Variable[] values = new Variable[getColumnCount()];
        int lastChangedColumn =
                getChangesFromRequest(row.getIndex(), row, subRequest,
                        values, newRow, newRow);
        ChangeSet changeSet = new ChangeSet(row.getIndex(), values);
        changeSet.lastChangedColumn = lastChangedColumn;
        rowMap.put(row.getIndex(), changeSet);
        return changeSet;
    }


    protected ChangeSet getPendingChangeSet(SubRequest<?> subRequest, OID index) {
        if (pendingChanges != null) {
            Map<OID, ChangeSet> rowMap = pendingChanges.get(subRequest.getRequest());
            if (rowMap != null) {
                return rowMap.get(index);
            }
        }
        return null;
    }

    /**
     * Gets a {@link ChangeSet} that contains the row values as if they had been already committed (not taking into
     * account value modifications performed by the columns commit operations). This method can be called when
     * processing commits of other {@link ManagedObject}s on behalf of the same SNMP request to determine what a certain
     * row will contain if the this SET will be successful.
     *
     * @param request
     *         the request to preview. If {@code null} or no pending changes exist for this request, the current row
     *         values are returned.
     * @param index
     *         the row index of the row to return.
     *
     * @return the values as if the provided {@code request} has already been committed of the row identified by {@code
     * index}.
     * @since 3.0
     */
    public ChangeSet getRowPreview(Request<?, ?, ?> request, OID index) {
        ChangeSet changeSet = null;
        if (pendingChanges != null) {
            Map<OID, ChangeSet> rowMap = pendingChanges.get(request);
            if (rowMap != null) {
                changeSet = rowMap.get(index);
            }
        }
        R tableRow = model.getRow(index);
        if (tableRow == null) {
            return null;
        }
        if (changeSet == null) {
            Variable[] values = new Variable[getColumnCount()];
            changeSet = new ChangeSet(index, values);
        }
        for (int i = 0; i < changeSet.values.length; i++) {
            if (changeSet.values[i] == null) {
                changeSet.values[i] = tableRow.getValue(i);
            }
        }
        return changeSet;
    }

    public void cleanup(SubRequest<?> request) {
        OID cellOID = request.getVariableBinding().getOid();
        MOTableCellInfo cell = getCellInfo(cellOID);
        if ((cell.getIndex() == null) || (cell.getColumn() < 0)) {
            return;
        }
        MOColumn<?> col = getColumn(cell.getColumn());
        if (logger.isDebugEnabled()) {
            logger.debug("Cleaning-up sub-request (" +
                    request.getVariableBinding() + ") for column: " + col);
        }
        MOMutableTableRow row = (MOMutableTableRow) model.getRow(cell.getIndex());
        if ((row != null) && (col instanceof MOMutableColumn)) {
            ((MOMutableColumn<?>) col).cleanup(request, row, cell.getColumn());
        }
        if ((row instanceof MOMutableRow2PC) &&
                isChangeSetComplete(request, row.getIndex(), cell.getColumn())) {
            @SuppressWarnings("unchecked")
            MOMutableRow2PC<SubRequest<?>> mutableRow2PC = (MOMutableRow2PC<SubRequest<?>>) row;
            mutableRow2PC.cleanupRow(request, getPendingChangeSet(request,
                    row.getIndex()));
        }
        request.completed();
    }

    public void undo(SubRequest<?> request) {
        OID cellOID = request.getVariableBinding().getOid();
        MOTableCellInfo cell = getCellInfo(cellOID);
        MOMutableColumn<?> col = (MOMutableColumn) getColumn(cell.getColumn());
        if (logger.isDebugEnabled()) {
            logger.debug("Undoing sub-request (" +
                    request.getVariableBinding() + ") for column: " + col);
        }
        if (hasNewRows(request.getRequest())) {
            ((MOMutableTableModel) model).removeRow(cell.getIndex());
        } else {
            MOMutableTableRow row = (MOMutableTableRow) model.getRow(cell.getIndex());
            if (row != null) {
                col.undo(request, row, cell.getColumn());
            }
            if ((row instanceof MOMutableRow2PC) &&
                    isChangeSetComplete(request, row.getIndex(), cell.getColumn())) {
                @SuppressWarnings("unchecked")
                MOMutableRow2PC<SubRequest<?>> mutableRow2PC = (MOMutableRow2PC<SubRequest<?>>) row;
                mutableRow2PC.undoRow(request, getPendingChangeSet(request, row.getIndex()));
            }
        }
    }

    public OID getOID() {
        return oid;
    }

    public void setModel(M model) {
        this.model = model;
    }

    public void setVolatile(boolean isVolatile) {
        this.isVolatile = isVolatile;
    }

    public M getModel() {
        return model;
    }

    public C[] getColumns() {
        return columns;
    }

    public MOTableIndex getIndexDef() {
        return indexDef;
    }

    public boolean isVolatile() {
        return isVolatile;
    }

    public OID getLowerBound() {
        return oid;
    }

    public OID getUpperBound() {
        OID upperBound = new OID(oid);
        int lastID = oid.size() - 1;
        /*
         * This is not quite correct because we would have to search up the tree
         * if the last sub ID is 0xFFFFFFFF, but since a table OID must end on 1
         * by SMI rules we should be on the safe side here.
         */
        upperBound.set(lastID, oid.get(lastID) + 1);
        return upperBound;
    }

    public boolean isLowerIncluded() {
        return false;
    }

    public boolean isUpperIncluded() {
        return false;
    }

    public boolean isCovered(MOScope other) {
        return DefaultMOScope.covers(this, other);
    }

    public boolean isOverlapping(MOScope other) {
        return DefaultMOScope.overlaps(this, other);
    }

    public synchronized void addMOChangeListener(MOChangeListener l) {
        if (moChangeListeners == null) {
            moChangeListeners = new ArrayList<>(2);
        }
        moChangeListeners.add(l);
    }

    public synchronized void removeMOChangeListener(MOChangeListener l) {
        if (moChangeListeners != null) {
            moChangeListeners.remove(l);
        }
    }

    protected void fireBeforePrepareMOChange(MOChangeEvent changeEvent) {
        if (moChangeListeners != null) {
            List<MOChangeListener> listeners = moChangeListeners;
            for (MOChangeListener listener : listeners) {
                listener.beforePrepareMOChange(changeEvent);
            }
        }
    }

    protected void fireAfterPrepareMOChange(MOChangeEvent changeEvent) {
        if (moChangeListeners != null) {
            List<MOChangeListener> listeners = moChangeListeners;
            for (MOChangeListener listener : listeners) {
                listener.afterPrepareMOChange(changeEvent);
            }
        }
    }

    protected void fireBeforeMOChange(MOChangeEvent changeEvent) {
        if (moChangeListeners != null) {
            List<MOChangeListener> listeners = moChangeListeners;
            for (MOChangeListener listener : listeners) {
                listener.beforeMOChange(changeEvent);
            }
        }
    }

    protected void fireAfterMOChange(MOChangeEvent changeEvent) {
        if (moChangeListeners != null) {
            List<MOChangeListener> listeners = moChangeListeners;
            for (MOChangeListener listener : listeners) {
                listener.afterMOChange(changeEvent);
            }
        }
    }

    public synchronized void addMOTableRowListener(MOTableRowListener<R> l) {
        if (moTableRowListeners == null) {
            moTableRowListeners = new ArrayList<>(2);
        }
        fireRowExistsEvent(l);
        moTableRowListeners.add(l);
    }

    /**
     * Gets the row with the given index from the dependent table (thus a table which extends this table using a {@link
     * MOTableRelation}) with the provided table entry object identifier.
     *
     * @param dependentTableID
     *         the OID of the {@link MOTable} that is linked with a {@link MOTableRelation} as dependent table.
     * @param index
     *         the row index of the dependent's table row that should be returned.
     *
     * @return a {@link MOTableRow} if such a row exists or {@code null} otherwise.
     * @since 3.0
     */
    public MOTableRow getDependentTableRow(OID dependentTableID, OID index) {
        if (this.moTableRowListeners == null) {
            return null;
        }
        List<MOTableRowListener<R>> listeners;
        synchronized (this) {
            listeners = new ArrayList<>(this.moTableRowListeners);
        }
        for (MOTableRowListener<R> tableRowListener : listeners) {
            if (tableRowListener instanceof MOTableRelation.RelationShipListener) {
                @SuppressWarnings("unchecked")
                MOTableRelation<R, ?>.RelationShipListener tableRelation =
                        (MOTableRelation.RelationShipListener) tableRowListener;
                if (dependentTableID.equals(tableRelation.getDependentTable().getOID())) {
                    // found table, now look for matching row
                    return tableRelation.getDependentTable().getModel().getRow(index);
                }
            }
        }
        return null;
    }

    /**
     * Fires a {@link MOTableRowEvent#EXISTS} for all rows in this table if the provided listener actively subscribes to
     * all such events this time by setting {@link MOTableRowEvent#setSendNextEventsOfSameOrigin(boolean)} to {@code
     * true} on the first rows and following events.
     *
     * @param l
     *         the table row listener.
     */
    protected void fireRowExistsEvent(MOTableRowListener<R> l) {
        int rowCount = model.getRowCount();
        int retries = rowCount;
        if (rowCount > 0) {
            Iterator<R> it = model.iterator();
            OID lastIndex = null;
            if (it.hasNext()) {
                MOTableRowEvent<R> rowEvent = null;
                boolean changed = false;
                do {
                    try {
                        retries--;
                        R firstRow = it.next();
                        lastIndex = firstRow.getIndex();
                        rowEvent = new MOTableRowEvent<R>(this, this, firstRow, null,
                                MOTableRowEvent.EXISTS, false, --rowCount);
                        changed = false;
                        l.rowChanged(rowEvent);
                    } catch (ConcurrentModificationException cmex) {
                        changed = true;
                        rowCount++;
                    }
                }
                while (changed && (retries > 0));
                while ((rowEvent != null) && rowEvent.isSendNextEventsOfSameOrigin() && it.hasNext()) {
                    try {
                        rowEvent = new MOTableRowEvent<R>(this, this, it.next(), null, MOTableRowEvent
                                .EXISTS, false, --rowCount);
                        lastIndex = rowEvent.getRow().getIndex();
                        l.rowChanged(rowEvent);
                    } catch (ConcurrentModificationException cmex) {
                        rowCount++;
                        it = model.tailIterator(lastIndex);
                    }
                }
            }
        }
    }

    public synchronized void removeMOTableRowListener(MOTableRowListener<R> l) {
        if (moTableRowListeners != null) {
            moTableRowListeners.remove(l);
        }
    }

    protected void fireRowChanged(MOTableRowEvent<R> event) {
        if (moTableRowListeners != null) {
            List<MOTableRowListener<R>> listeners = moTableRowListeners;
            for (MOTableRowListener<R> listener : listeners) {
                listener.rowChanged(event);
            }
        }
    }

    @Override
    public boolean importInstance(OID instanceID, List<VariableBinding> data, ImportMode importMode) {
        if (data.size() > 0) {
            // columns must be ascending order in the data, so get the last col ID to determine array size
            int colCount = getColumnCount();
            int startPos = Math.min(colCount, data.size()) - 1;
            int maxRegularColIndex = colCount - 1;
            int numAdditionalColumns = 0;
            for (int i = startPos; i < data.size(); i++) {
                int colId = data.get(i).getOid().get(0);
                int colIndex = (colId >= 0) ? getColumnIndex(colId) : 0;
                if (colId >= 0 && (colIndex >= 0) && (colIndex > maxRegularColIndex)) {
                    maxRegularColIndex = colIndex;
                } else if (colId < 0) {
                    numAdditionalColumns++;
                }
            }
            Variable[] variables = new Variable[maxRegularColIndex + 1 + numAdditionalColumns];
            int colIndex = 0;
            for (VariableBinding vb : data) {
                int colId = vb.getOid().get(0);
                if (colId >= 0) {
                    int nextColIndex = getColumnIndex(colId);
                    if (nextColIndex < 0) {
                        colIndex = maxRegularColIndex + Math.abs(colId) - maxRegularColIndex;
                    } else {
                        colIndex = nextColIndex;
                    }
                } else {
                    colIndex = maxRegularColIndex + Math.abs(colId) - maxRegularColIndex;
                }
                if (colIndex >= 0 && colIndex < variables.length && !(vb.getVariable() instanceof Null)) {
                    variables[colIndex] = vb.getVariable();
                }
            }
            for (int i = 0; i < getColumnCount(); i++) {
                MOColumn<?> column = getColumn(i);
                variables[i] = column.getRestoreValue(variables, i);
            }
            if (instanceID != null && instanceID.size() > 0) {
                try {
                    loadRow(instanceID, variables, importMode.ordinal());
                } catch (ArrayIndexOutOfBoundsException aioobex) {
                    logger.error("Unable to load persistent row, because it has too few columns: " +
                            Arrays.asList(variables) + ", raw data:" + data, aioobex);
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Tests if the specified instance should be serialized or deserialized through persistent storage load or save
     * operation.
     *
     * @param instanceSubID
     *         the OID suffix identifying the instance to check, for scalars this is "0" and for tabular objects this is
     *         the row index.
     *
     * @return {@code true} if the specified sub-instance exists and is {@link StorageType#volatile_}.
     * @since 3.2.0
     */
    @Override
    public boolean isVolatile(OID instanceSubID) {
        if (instanceSubID != null) {
            R row = model.getRow(instanceSubID);
            if (row != null) {
                return isVolatileRow(row);
            }
        }
        return false;
    }

    @Override
    public List<VariableBinding> exportInstance(OID instanceID) {
        if (instanceID == null) {
            return null;
        }
        R row = model.getRow(instanceID);
        if (row == null) {
            return null;
        }
        ArrayList<VariableBinding> exports = new ArrayList<>(row.size());
        // add values
        for (int i = 0, y = -getColumn(getColumnCount() - 1).getColumnID(); i < row.size(); i++) {
            Variable v = row.getValue(i);
            if (i < getColumnCount()) {
                v = getColumn(i).getStoreValue(row, i);
            }
            if (v != null && (i < getColumnCount() - 1)) {
                int colID = (i < getColumnCount()) ? getColumn(i).getColumnID() : --y;
                exports.add(new VariableBinding(new OID(new int[]{colID}), v));
            } else if (i >= getColumnCount() - 1) {
                int colID = (i < getColumnCount()) ? getColumn(i).getColumnID() : --y;
                if (v == null) {
                    exports.add(new VariableBinding(new OID(new int[]{colID})));
                } else {
                    exports.add(new VariableBinding(new OID(new int[]{colID}), v));
                }
            }
        }
        return exports;
    }

    @Override
    public Iterator<OID> instanceIterator() {

        return new Iterator<OID>() {
            Iterator<R> rowIterator = model.iterator();

            @Override
            public boolean hasNext() {
                return rowIterator.hasNext();
            }

            @Override
            public OID next() {
                return rowIterator.next().getIndex();
            }
        };
    }

    /**
     * Returns the instance sub-identifier suffix for the given instance OID. Any implementations of this method must
     * use the same instance notion of instance identifier as {@link #importInstance(OID, List, ImportMode)}, {@link
     * #exportInstance(OID)}, and {@link #instanceIterator()}.
     *
     * @param instanceOID
     *         the fully qualified {@link OID} of a SNMP {@link Variable}.
     *
     * @return the instance ID that uniquely identifies the object instance the specified {@link Variable} belongs to
     * within this {@link RandomAccessManagedObject}.
     */
    @Override
    public OID getInstanceSubID(OID instanceOID) {
        OID suffix = instanceOID.getSuffix(getOID());
        // We cut off the column ID here, because we want to safe tabular data by rows, not by cells.
        return new OID(suffix.getValue(), 1, suffix.size() - 1);
    }

    /**
     * Returns the number of instances managed by this {@link ManagedObject}.
     *
     * @return the number of instances managed by this object.
     */
    @Override
    public int instanceCount() {
        return model.getRowCount();
    }

    public static class ChangeSet implements MOTableRow {

        private OID index;
        private Variable[] values;
        private int lastChangedColumn = -1;

        public ChangeSet(OID index, Variable[] values) {
            this.index = index;
            this.values = values;
        }

        public OID getIndex() {
            return index;
        }

        public int getLastChangedColumn() {
            return lastChangedColumn;
        }

        public void setValue(int column, Variable value) {
            values[column] = value;
            this.lastChangedColumn = column;
        }

        public Variable getValue(int column) {
            return values[column];
        }

        public MOTableRow getBaseRow() {
            return null;
        }

        public int size() {
            return values.length;
        }

        public void setBaseRow(MOTableRow baseRow) {
            throw new UnsupportedOperationException();
        }
    }

    class CellProxy implements ManagedObject<SubRequest<?>> {

        private MOTableCellInfo cellInfo;
        private MOScope scope;

        public CellProxy(MOTableCellInfo cellInfo) {
            this.cellInfo = cellInfo;
            this.scope = new OIDScope(cellInfo.getCellOID());
        }

        public MOScope getScope() {
            return scope;
        }

        public OID find(MOScope range) {
            if (range.isCovered(scope)) {
                return cellInfo.getCellOID();
            }
            return null;
        }

        public void get(SubRequest<?> request) {
            DefaultMOTable.this.get(request);
        }

        public boolean next(SubRequest<?> request) {
            return DefaultMOTable.this.next(request);
        }

        public void prepare(SubRequest<?> request) {
            DefaultMOTable.this.prepare(request);
        }

        public void commit(SubRequest<?> request) {
            DefaultMOTable.this.commit(request);
        }

        public void undo(SubRequest<?> request) {
            DefaultMOTable.this.undo(request);
        }

        public void cleanup(SubRequest<?> request) {
            DefaultMOTable.this.cleanup(request);
        }

        public MOTable<R, C, M> getTable() {
            return DefaultMOTable.this;
        }
    }

    static class CellInfo implements MOTableCellInfo {

        private OID index;
        private int id = 0;
        private int col = -1;
        private MOTableRow row;
        private DefaultMOTable<?, ?, ?> table;

        public CellInfo(DefaultMOTable<?, ?, ?> table, OID oid) {
            this.table = table;
            this.index = table.getIndexPart(oid);
            if ((oid.size() > table.oid.size()) &&
                    (oid.startsWith(table.oid))) {
                id = oid.get(table.oid.size());
            }
        }

        public CellInfo(DefaultMOTable<?, ?, ?> table, OID index, int column, int columnID) {
            this.table = table;
            this.index = index;
            this.col = column;
            this.id = columnID;
        }

        public CellInfo(DefaultMOTable<?, ?, ?> table, OID index, int column, int columnID, MOTableRow row) {
            this(table, index, column, columnID);
            this.row = row;
        }

        public OID getIndex() {
            return index;
        }

        public int getColumn() {
            if (col < 0) {
                col = table.getColumnIndex(id);
            }
            return col;
        }

        public int getColumnID() {
            return id;
        }

        public OID getCellOID() {
            return table.getCellOID(index, col);
        }

        public MOTableRow getRow() {
            return row;
        }

        @Override
        public String toString() {
            return "CellInfo{" +
                    "index=" + index +
                    ", id=" + id +
                    ", col=" + col +
                    ", row=" + row +
                    ", table=" + table +
                    '}';
        }
    }

    public OID getID() {
        return getLowerBound();
    }

    @SuppressWarnings("unchecked")
    @Override
    public void load(MOInput input) throws IOException {
        if (input.getImportMode() == ImportMode.REPLACE_CREATE) {
            int count = removeAll();
            if (logger.isDebugEnabled()) {
                logger.debug("Removed " + count + " rows from " + getID() +
                        " because importing with a REPLACE import mode");
            }
        } else if (input.getImportMode() == ImportMode.RESTORE_CHANGES) {
            int count =
                    removeAnyStorageType(new HashSet<>(Collections.singletonList(StorageType.StorageTypeEnum.nonVolatile)));
            if (logger.isDebugEnabled()) {
                logger.debug("Removed " + count + " rows from " + getID() +
                        "with storage type 'nonVolatile' because importing with a RESTORE_CHANGES import mode");
            }
        }
        Sequence seq = input.readSequence();
        for (int i = 0; i < seq.getSize(); i++) {
            IndexedVariables rowValues = input.readIndexedVariables();
            Variable[] rawRowValues = rowValues.getValues();
            // map raw values from storage to restored values
            for (int c = 0; ((c < rawRowValues.length) && (c < getColumnCount())); c++) {
                rawRowValues[c] = getColumn(c).getRestoreValue(rawRowValues, c);
            }
            // verify that index is valid
            MOTableIndex tableIndex = getIndexDef();
            if (!tableIndex.isValidIndex(rowValues.getIndex())) {
                logger.warn("Unable to load row with index '" + rowValues.getIndex() + "' into table '" + getOID() +
                        "' because of invalid index");
                continue;
            }
            int importMode = input.getImportMode();
            loadRow(rowValues.getIndex(), rawRowValues, importMode);
        }
    }

    @SuppressWarnings("unchecked")
    protected void loadRow(OID rowIndex, Variable[] rawRowValues, int importMode) {
        R existingRow = model.getRow(rowIndex);
        boolean rowExists = (existingRow != null);
        if ((importMode == ImportMode.CREATE) && (rowExists)) {
            logger.debug("Row '" + rowIndex + "' not imported because it already exists in table " +
                    getID() + " and import mode is CREATE");
            return;
        }
        if (rowExists && !(existingRow instanceof MOMutableTableRow)) {
            R previousRow = removeRow(rowIndex);
            if (previousRow != null && logger.isDebugEnabled()) {
                logger.debug("Replacing row " + previousRow);
            }
        } else if (rowExists) {
            MOMutableTableRow mutableTableRow = (MOMutableTableRow) existingRow;
            for (int c = 0; c < rawRowValues.length; c++) {
                // check if this is a value of a regular column, otherwise no event will be fired
                if (c < columns.length) {
                    MOColumn<?> moColumn = getColumn(c);
                    rawRowValues[c] = moColumn.getRestoreValue(rawRowValues, c);
                    MOTableCellInfo cellInfo = new CellInfo(this, rowIndex, c, columns[c].getColumnID());
                    if (moChangeListeners != null) {
                        MOChangeEvent changeEvent =
                                new MOChangeEvent(this, this, cellInfo.getCellOID(), existingRow.getValue(c),
                                        rawRowValues[c], true);
                        fireBeforePrepareMOChange(changeEvent);
                        if (changeEvent.getDenyReason() != PDU.noError) {
                            logger.info("Value not loaded because update denied: " + changeEvent);
                            continue;
                        }
                    }
                }
                if (c < mutableTableRow.size()) {
                    try {
                        mutableTableRow.setValue(c, rawRowValues[c]);
                    } catch (ClassCastException ccex) {
                        logger.error("Failed to load data for row " + rowIndex + " in table " +
                                getOID() + " column " + c + " and new value " + rawRowValues[c]);
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Ignored additional column data at position " + c + " with value " + rawRowValues[c]);
                    }
                }
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Updated row " + existingRow);
            }
            if (moTableRowListeners != null) {
                MOTableRowEvent<R> rowEvent =
                        new MOTableRowEvent<R>(this, this, existingRow, MOTableRowEvent.UPDATED,
                                MOTableRowEvent.OriginType.internal);
                fireRowChanged(rowEvent);
            }
        }
        if (((!rowExists) && (importMode != ImportMode.UPDATE)) || !(existingRow instanceof MOMutableTableRow)) {
            try {
                existingRow = createRowInternal(rowIndex, rawRowValues, MOTableRowEvent.OriginType.internal);
            } catch (UnsupportedOperationException uoex) {
                logger.debug("Could not create row by row factory: " +
                        uoex.getMessage());
                // ignore
            }
            if (existingRow == null) {
                //noinspection unchecked
                existingRow = (R) new DefaultMOTableRow(rowIndex, rawRowValues);
                MOTableRowEvent<R> rowEvent =
                        new MOTableRowEvent<R>(this, this, existingRow, MOTableRowEvent.CREATE,
                                MOTableRowEvent.OriginType.internal);
                fireRowChanged(rowEvent);
            }
            if (addRowInternal(existingRow, MOTableRowEvent.OriginType.internal)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Loaded row " + existingRow + " into table " + getOID());
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void save(MOOutput output) throws IOException {
        List<IndexedVariables> rowsToSave = new LinkedList<IndexedVariables>();
        synchronized (model) {
            for (Iterator<R> it = model.iterator(); it.hasNext(); ) {
                R row = it.next();
                boolean volatileRow = isVolatileRow(row);
                if (!volatileRow) {
                    Variable[] values = getPersistentValues(row);
                    IndexedVariables rowValues = new IndexedVariables(row.getIndex(), values);
                    rowsToSave.add(rowValues);
                }
            }
        }
        Sequence group = new Sequence(rowsToSave.size());
        output.writeSequence(group);
        for (IndexedVariables rowValues : rowsToSave) {
            output.writeIndexedVariables(rowValues);
        }
    }

    private boolean isVolatileRow(R row) {
        boolean volatileRow = false;
        for (int i = 0; i < columns.length; i++) {
            if (columns[i].isVolatile(row, i)) {
                volatileRow = true;
                break;
            }
        }
        return volatileRow;
    }

    /**
     * Gets the values of a row that need to be made persistent on behalf of a {@link #save(MOOutput output)} call.
     *
     * @param row
     *         a MOTableRow that is being saved into a MOOutput stream.
     *
     * @return an array of {@code Variable} instances that need to be saved. Typically, these are all columns of the row
     * - including hidden extension columns/values.
     * @since 1.2
     */
    protected Variable[] getPersistentValues(MOTableRow row) {
        Variable[] values = new Variable[row.size()];
        for (int i = 0; (i < values.length); i++) {
            if (i < getColumnCount()) {
                MOColumn<?> column = getColumn(i);
                values[i] = column.getStoreValue(row, i);
            } else {
                // Hidden columns are persistent by default:
                values[i] = row.getValue(i);
            }
        }
        return values;
    }

    public Variable[] getDefaultValues() {
        Variable[] values = new Variable[getColumnCount()];
        for (int i = 0; (i < values.length); i++) {
            if (columns[i] instanceof MOMutableColumn) {
                values[i] = ((MOMutableColumn) columns[i]).getDefaultValue();
            }
        }
        return values;
    }

    public String toString() {
        return "DefaultMOTable[id=" + getID() + ",index=" + getIndexDef() + ",columns=" +
                Arrays.asList(getColumns()) + "]";
    }

    public boolean covers(OID oid) {
        return isCovered(new DefaultMOScope(oid, true, oid, true));
    }

    public boolean setValue(VariableBinding newValueAndInstancceOID) {
        MOTableCellInfo cell = getCellInfo(newValueAndInstancceOID.getOid());
        if (cell != null) {
            MOColumn<?> col = getColumn(cell.getColumn());
            if (logger.isDebugEnabled()) {
                logger.debug("Setting value " + newValueAndInstancceOID + " for column: " + col);
            }
            // Make sure changes are atomic -> sync whole table model
            MOTableRow row;
            synchronized (model) {
                row = model.getRow(cell.getIndex());
                if (row instanceof MOMutableTableRow) {
                    ((MOMutableTableRow) row).setValue(cell.getColumn(), newValueAndInstancceOID.getVariable());
                    return true;
                }
            }
        }
        return false;
    }

    private static class RowCacheEntry {
        private MOTableRow row;
        private OID searchLowerBound;
        private boolean searchLowerBoundIncluded;

        RowCacheEntry(MOTableRow row,
                      OID searchLowerBound, boolean searchLowerBoundIncluded) {
            this.row = row;
            this.searchLowerBound = searchLowerBound;
            this.searchLowerBoundIncluded = searchLowerBoundIncluded;
        }
    }
}
