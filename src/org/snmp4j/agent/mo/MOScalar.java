/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOScalar.java  
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

import java.io.*;
import java.util.*;

import org.snmp4j.agent.*;
import org.snmp4j.agent.io.*;
import org.snmp4j.agent.request.*;
import org.snmp4j.mp.*;
import org.snmp4j.smi.*;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;

/**
 * The {@code MOScalar} class represents scalar SNMP managed objects.
 * Subclasses might support Java serialization for this class. SNMP4J
 * serialization is provided in any case by the {@link SerializableManagedObject}
 * interface.
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public class MOScalar<V extends Variable> implements GenericManagedObject, MOScope,
        SerializableManagedObject<SubRequest<?>>, ManagedObjectValueAccess<SubRequest<?>>,
        ChangeableManagedObject<SubRequest<?>>, RandomAccessManagedObject<SubRequest<?>> {

    private static LogAdapter logger = LogFactory.getLogger(MOScalar.class);

    protected OID oid;
    private volatile OID lowerBound;
    private volatile OID upperBound;
    private V value;
    protected MOAccess access;
    private boolean isVolatile;
    private transient List<MOValueValidationListener> moValueValidationListeners;
    private transient List<MOChangeListener> moChangeListeners;

    /**
     * Construct a MOScalar for deserialization. If used by a subclass, make sure
     * the {@link #oid} and {@link #access} members are set before the scalar is
     * registered with a {@link MOServer} instance. The {@link #oid} must not be
     * changed or modified afterwards!
     *
     * @since 2.4.1
     */
    protected MOScalar() {
    }

    /**
     * Creates a scalar MO instance with OID, maximum access level and initial
     * value.
     *
     * @param id     the instance OID of the scalar instance (last sub-identifier should be
     *               zero).
     * @param access the maximum access level supported by this instance.
     * @param value  the initial value of the scalar instance. If the initial value is
     *               {@code null} or a Counter syntax, the scalar is created as a
     *               volatile (non-persistent) instance by default.
     */
    public MOScalar(OID id, MOAccess access, V value) {
        this.oid = id;
        this.access = access;
        this.value = value;
        this.isVolatile = isVolatileByDefault(value);
    }

    private static boolean isVolatileByDefault(Variable value) {
        if (value == null) {
            return true;
        }
        switch (value.getSyntax()) {
            case SMIConstants.SYNTAX_COUNTER32:
            case SMIConstants.SYNTAX_COUNTER64: {
                return true;
            }
            default:
                return false;
        }
    }

    /**
     * Returns the scope of OIDs that are covered by this scalar's object
     * registration. This range is
     * {@code 1.3.6...n} &lt;= x &lt;  {@code 1.3.6...n+1} where n is the
     * last subidentifier of the OID registered by the corresponding OBJECT-TYPE
     * definition. Prior to version 1.1.2, this method returned a scope equal
     * to the scope now returned by {@link #getSingleInstanceScope()}.
     *
     * @return a MOScope that covers the OIDs by this scalar object registration.
     */
    public MOScope getScope() {
        return this;
    }

    /**
     * Returns a scope that covers only the scalar instance itself without any
     * possible OIDs down in the tree or at the same level.
     *
     * @return a scope that covers exactly the OID of this scalar.
     * @since 1.1.2
     */
    public MOScope getSingleInstanceScope() {
        return new DefaultMOScope(oid, true, oid, true);
    }

    public OID find(MOScope range) {
        if (access.isAccessibleForRead() &&
                range.isCovered(getSingleInstanceScope())) {
            if (logger.isDebugEnabled()) {
                logger.debug("MOScalar '" + oid + "' is in scope '" + range + "'");
            }
            return oid;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("MOScalar '" + oid + "' is not in scope '" + range + "'");
        }
        return null;
    }

    public void get(SubRequest<?> request) {
        RequestStatus status = request.getStatus();
        if (checkRequestScope(request)) {
            if (access.isAccessibleForRead()) {
                VariableBinding vb = request.getVariableBinding();
                vb.setOid(getOid());
                Variable variable = getValue();
                if (variable == null) {
                    vb.setVariable(Null.noSuchObject);
                } else {
                    vb.setVariable((Variable) variable.clone());
                }
                request.completed();
            } else {
                status.setErrorStatus(SnmpConstants.SNMP_ERROR_NO_ACCESS);
            }
        }
    }

    /**
     * Gets the access object for this scalar.
     *
     * @return the access instance associated with this scalar.
     * @since 1.2
     */
    public MOAccess getAccess() {
        return access;
    }

    /**
     * Checks whether the request is within the scope of this scalar or not.
     *
     * @param request a SubRequest.
     * @return {@code true} if the request is within scope and {@code false}
     * otherwise. In the latter case, the variable of the request is set
     * to {@link Null#noSuchInstance} and the request is marked completed.
     */
    protected boolean checkRequestScope(SubRequest<?> request) {
        if (!request.getVariableBinding().getOid().equals(oid)) {
            VariableBinding vb = request.getVariableBinding();
            vb.setOid(getOid());
            vb.setVariable(Null.noSuchInstance);
            request.completed();
            return false;
        }
        return true;
    }

    public boolean next(SubRequest<?> request) {
        if (access.isAccessibleForRead() &&
                (request.getScope().isCovered(getSingleInstanceScope()))) {
            VariableBinding vb = request.getVariableBinding();
            vb.setOid(getOid());
            Variable variable = getValue();
            if (variable == null) {
                // skip this scalar for NEXT requests
                if (logger.isDebugEnabled()) {
                    logger.debug("Skipped '" +
                            getOid() + "' for GETNEXT/BULK request '" + request + "' because variable is NULL");
                }
                return false;
            } else {
                vb.setVariable((Variable) variable.clone());
            }
            request.completed();
            if (logger.isDebugEnabled()) {
                logger.debug("Processed GETNEXT/BULK request '" + request + "' by '" +
                        getOid());
            }
            return true;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Skipped '" +
                    getOid() + "' for GETNEXT/BULK request '" + request + "'");
        }
        return false;
    }

    /**
     * Checks whether the new value contained in the supplied sub-request is a
     * valid value for this object. The checks are performed by firing a
     * {@link MOValueValidationEvent} the registered listeners.
     *
     * @param request the {@code SubRequest} with the new value.
     * @return {@link SnmpConstants#SNMP_ERROR_SUCCESS} if the new value is OK,
     * any other appropriate SNMPv2/v3 error status if not.
     */
    public int isValueOK(SubRequest<?> request) {
        if (moValueValidationListeners != null) {
            Variable oldValue = value;
            Variable newValue =
                    request.getVariableBinding().getVariable();
            MOValueValidationEvent event =
                    new MOValueValidationEvent(this, oldValue, newValue);
            fireValidate(event);
            return event.getValidationStatus();
        }
        return SnmpConstants.SNMP_ERROR_SUCCESS;
    }

    /**
     * Get the syntax of the scalars value by evaluating the internal cached value first. If that is {@code null},
     * the {@link #getValue()} method is called instead to allow subclasses to return an updated value.
     *
     * @return {@code value.getSyntax()} if value is not null and {@code getValue().,getSyntax()} if value is null.
     */
    protected int getSyntax() {
        return (value != null) ? value.getSyntax() : getValue().getSyntax();
    }

    public void prepare(SubRequest<?> request) {
        RequestStatus status = request.getStatus();
        if (oid.equals(request.getVariableBinding().getOid())) {
            if (access.isAccessibleForWrite()) {
                VariableBinding vb = request.getVariableBinding();
                if (vb.getVariable().getSyntax() != getSyntax()) {
                    status.setErrorStatus(SnmpConstants.SNMP_ERROR_WRONG_TYPE);
                    return;
                }
                Variable value = null;
                if (moChangeListeners != null) {
                    value = getValue();
                    MOChangeEvent event =
                            new MOChangeEvent(this, this,
                                    request.getVariableBinding().getOid(), value,
                                    request.getVariableBinding().getVariable(),
                                    true, request);
                    fireBeforePrepareMOChange(event);
                    if (event.getDenyReason() != SnmpConstants.SNMP_ERROR_SUCCESS) {
                        status.setErrorStatus(event.getDenyReason());
                        status.setPhaseComplete(true);
                        return;
                    }
                }
                int valueOK = isValueOK(request);
                if ((moChangeListeners != null) &&
                        (valueOK == SnmpConstants.SNMP_ERROR_SUCCESS)) {
                    MOChangeEvent event =
                            new MOChangeEvent(this, this,
                                    request.getVariableBinding().getOid(), value,
                                    request.getVariableBinding().getVariable(),
                                    true, request);
                    fireAfterPrepareMOChange(event);
                    valueOK = event.getDenyReason();
                }
                status.setErrorStatus(valueOK);
                status.setPhaseComplete(true);
            } else {
                status.setErrorStatus(SnmpConstants.SNMP_ERROR_NOT_WRITEABLE);
            }
        } else {
            status.setErrorStatus(SnmpConstants.SNMP_ERROR_NO_CREATION);
        }
    }

    @SuppressWarnings("unchecked")
    public void commit(SubRequest<?> request) {
        RequestStatus status = request.getStatus();
        VariableBinding vb = request.getVariableBinding();
        Variable value = getValue();
        if (moChangeListeners != null) {
            MOChangeEvent event =
                    new MOChangeEvent(this, this, vb.getOid(), value,
                            vb.getVariable(), false, request);
            fireBeforeMOChange(event);
        }
        request.setUndoValue(value);
        changeValue((V) vb.getVariable());
        status.setPhaseComplete(true);
        if (moChangeListeners != null) {
            MOChangeEvent event =
                    new MOChangeEvent(this, this, request.getVariableBinding().getOid(),
                            (Variable) request.getUndoValue(),
                            vb.getVariable(), false, request);
            fireAfterMOChange(event);
        }
    }

    /**
     * Changes the value of this scalar on behalf of a commit or undo operation.
     * Overwrite this method for easy and simple instrumentation. By default
     * {@link #setValue(Variable value)} is called.
     *
     * @param value the new value.
     * @return a SNMP error status if the operation failed (should be avoided).
     * @since 1.2
     */
    protected int changeValue(V value) {
        return setValue(value);
    }

    @SuppressWarnings("unchecked")
    public void undo(SubRequest<?> request) {
        RequestStatus status = request.getStatus();
        if ((request.getUndoValue() != null) &&
                (request.getUndoValue() instanceof Variable)) {
            int errorStatus = changeValue((V) request.getUndoValue());
            status.setErrorStatus(errorStatus);
            status.setPhaseComplete(true);
        } else {
            status.setErrorStatus(SnmpConstants.SNMP_ERROR_UNDO_FAILED);
        }
    }

    public void cleanup(SubRequest<?> request) {
        request.setUndoValue(null);
        request.getStatus().setPhaseComplete(true);
    }

    /**
     * Gets the instance OID of this scalar managed object.
     *
     * @return the instance OID (by reference).
     */
    public OID getOid() {
        return oid;
    }

    @Override
    public OID getLowerBound() {
        if (lowerBound == null) {
            lowerBound = new OID(oid.getValue(), 0, oid.size() - 1);
        }
        return lowerBound;
    }

    @Override
    public OID getUpperBound() {
        if (upperBound == null) {
            upperBound = new OID(getLowerBound().nextPeer());
        }
        return upperBound;
    }

    @Override
    public boolean isCovered(MOScope other) {
        return (other.getLowerBound().startsWith(oid) &&
                (other.getLowerBound().size() > oid.size() ||
                        other.isLowerIncluded())) &&
                (other.getUpperBound().startsWith(oid) &&
                        ((other.getUpperBound().size() > oid.size()) ||
                                other.isUpperIncluded()));
    }

    @Override
    public boolean isLowerIncluded() {
        return true;
    }

    @Override
    public boolean isUpperIncluded() {
        return false;
    }

    /**
     * Returns the actual value of this scalar managed object. For a basic
     * instrumentation, overwrite this method to provide always the actual
     * value and/or to update the internal {@code value} member and
     * then call {@code super.}{@link #getValue()} in the derived class.
     *
     * @return a non {@code null} Variable with the same syntax defined for
     * this scalar object.
     */
    public V getValue() {
        return value;
    }

    @Override
    public boolean isVolatile() {
        return isVolatile;
    }

    /**
     * Sets the value of this scalar managed object without checking it for
     * the correct syntax.
     *
     * @param value a Variable with the with the same syntax defined for
     *              this scalar object (not checked).
     * @return a SNMP error code (zero indicating success by default).
     */
    public int setValue(V value) {
        this.value = value;
        return SnmpConstants.SNMP_ERROR_SUCCESS;
    }

    /**
     * Sets the volatile flag for this instance.
     *
     * @param isVolatile if {@code true} the state of this object will not be persistently
     *                   stored, otherwise the agent may save the state of this object
     *                   persistently.
     */
    public void setVolatile(boolean isVolatile) {
        this.isVolatile = isVolatile;
    }

    @Override
    public boolean isOverlapping(MOScope other) {
        return DefaultMOScope.overlaps(this, other);
    }

    /**
     * Adds a value validation listener to check new values.
     *
     * @param l a {@code MOValueValidationListener} instance.
     */
    public synchronized void addMOValueValidationListener(
            MOValueValidationListener l) {
        if (moValueValidationListeners == null) {
            moValueValidationListeners = new ArrayList<>(2);
        }
        moValueValidationListeners.add(l);
    }

    /**
     * Removes a value validation listener
     *
     * @param l a {@code MOValueValidationListener} instance.
     */
    public synchronized void removeMOValueValidationListener(
            MOValueValidationListener l) {
        if (moValueValidationListeners != null) {
            moValueValidationListeners.remove(l);
        }
    }

    protected synchronized void fireValidate(MOValueValidationEvent validationEvent) {
        List<MOValueValidationListener> listeners = moValueValidationListeners;
        if (listeners != null) {
            int count = listeners.size();
            for (MOValueValidationListener listener : listeners) {
                listener.validate(validationEvent);
            }
        }
    }

    @Override
    public OID getID() {
        return getOid();
    }

    @SuppressWarnings("unchecked")
    public synchronized void load(MOInput input) throws IOException {
        Variable v = input.readVariable();
        setValue((V) v);
    }

    public synchronized void save(MOOutput output) throws IOException {
        output.writeVariable(value);
    }

    public boolean covers(OID oid) {
        return oid.startsWith(this.oid);
    }

    public String toString() {
        return getClass().getName() + "[oid=" + getOid() + ",access=" + access +
                ",value=" + getValue() +
                ",volatile=" + isVolatile() + toStringDetails() + "]";
    }

    protected String toStringDetails() {
        return "";
    }

    /**
     * Adds a {@code MOChangeListener} that needs to be informed about
     * state changes of this scalar.
     *
     * @param l a {@code MOChangeListener} instance.
     * @since 1.1
     */
    public synchronized void addMOChangeListener(MOChangeListener l) {
        if (moChangeListeners == null) {
            moChangeListeners = new ArrayList<>(2);
        }
        moChangeListeners.add(l);
    }

    /**
     * Removes a {@code MOChangeListener}.
     *
     * @param l a {@code MOChangeListener} instance.
     * @since 1.1
     */
    public synchronized void removeMOChangeListener(MOChangeListener l) {
        if (moChangeListeners != null) {
            moChangeListeners.remove(l);
        }
    }

    protected synchronized void fireBeforePrepareMOChange(MOChangeEvent changeEvent) {
        List<MOChangeListener> listeners = moChangeListeners;
        if (listeners != null) {
            for (MOChangeListener listener : listeners) {
                listener.beforePrepareMOChange(changeEvent);
            }
        }
    }

    protected synchronized void fireAfterPrepareMOChange(MOChangeEvent changeEvent) {
        List<MOChangeListener> listeners = moChangeListeners;
        if (listeners != null) {
            for (MOChangeListener listener : listeners) {
                listener.afterPrepareMOChange(changeEvent);
            }
        }
    }

    protected synchronized void fireBeforeMOChange(MOChangeEvent changeEvent) {
        List<MOChangeListener> listeners = moChangeListeners;
        if (listeners != null) {
            for (MOChangeListener listener : listeners) {
                listener.beforeMOChange(changeEvent);
            }
        }
    }

    protected synchronized void fireAfterMOChange(MOChangeEvent changeEvent) {
        List<MOChangeListener> listeners = moChangeListeners;
        if (listeners != null) {
            for (MOChangeListener listener : listeners) {
                listener.afterMOChange(changeEvent);
            }
        }
    }

    public Variable getValue(OID instanceOID) {
        if (getOid().equals(instanceOID)) {
            return getValue();
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public boolean setValue(VariableBinding newValueAndInstancceOID) {
        if (getOid().equals(newValueAndInstancceOID.getOid())) {
            return (setValue((V) newValueAndInstancceOID.getVariable()) == SnmpConstants.SNMP_ERROR_SUCCESS);
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean importInstance(OID instanceID, List<VariableBinding> data, ImportMode importMode) {
        if (data.size() > 0) {
            try {
                Variable newValue = data.get(0).getVariable();
                if (newValue.getSyntax() == value.getSyntax()) {
                    /* unchecked */
                    if (logger.isDebugEnabled()) {
                        logger.debug("Loading scalar "+getOid()+" data "+newValue+" will overwrite "+getValue());
                    }
                    setValue((V) newValue);
                    return true;
                }
            } catch (Exception iox) {
                logger.error("Loading scalar "+getOid()+" failed: "+iox.getMessage(), iox);
            }
        }
        logger.error("Unable to load scalar data "+data+" for "+getOid());
        return false;
    }

    @Override
    public List<VariableBinding> exportInstance(OID instanceID) {
        Variable valueCopy = value;
        if (valueCopy == null) {
            return null;
        }
        List<VariableBinding> exportData =
                Collections.singletonList(new VariableBinding(new OID(new int[] {0}), valueCopy));
        if (logger.isDebugEnabled()) {
            logger.debug("Exporting scalar "+getOid()+" data: "+exportData);
        }
        return exportData;
    }

    @Override
    public Iterator<OID> instanceIterator() {
        return new Iterator<OID>() {
            OID next = new OID(new int[] { 0 });
            @Override
            public boolean hasNext() {
                return next != null;
            }

            @Override
            public OID next() {
                OID result = next;
                next = null;
                return result;
            }
        };
    }

    /**
     * Returns the number of instances managed by this {@link ManagedObject}.
     *
     * @return the number of instances managed by this object.
     */
    @Override
    public int instanceCount() {
        return 1;
    }
}
