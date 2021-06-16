/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOChangeEvent.java  
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
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.smi.*;

/**
 * The {@code MOChangeEvent} describes the change of a single value of
 * a {@code ManagedObject}.
 *
 * @author Frank Fock
 * @version 3.2.3
 */
public class MOChangeEvent extends DeniableEventObject {

    private static final long serialVersionUID = 2377168127200875177L;

    public enum Modification {
        created,
        added,
        updated,
        removed
    };

    public enum OidType {
        fullyQualified,
        instanceSuffix,
        index
    }

    private ManagedObject<SubRequest<?>> changedObject;
    private OID oid;
    private Variable oldValue;
    private Variable newValue;
    private Modification modification;
    private OidType oidType;
    private SubRequest<?> subRequest;


    /**
     * Creates a deniable {@code MOChangeEvent} object based on the changed
     * managed object, the instance OID of the changed value, with old and new
     * value.
     *
     * @param source
     *         the event source.
     * @param changedObject
     *         the {@code ManagedObject} whose value is changed.
     * @param oid
     *         the instance OID of the changed instance.
     * @param oldValue
     *         the old value.
     * @param newValue
     *         the new value.
     */
    public MOChangeEvent(Object source, ManagedObject<SubRequest<?>> changedObject,
                         OID oid, Variable oldValue, Variable newValue) {
        this(source, changedObject, oid, oldValue, newValue, true, null);
    }

    protected Modification getModificationFromValues(Variable oldValue, Variable newValue) {
        if ((oldValue == null) && (newValue != null)) {
            return Modification.added;
        }
        else if ((oldValue != null) && (newValue == null)) {
            return Modification.removed;
        }
        return Modification.updated;
    }

    /**
     * Creates a deniable {@code MOChangeEvent} object based on the changed
     * managed object instances that are identified through a common the instance OID (i.e. their row index)
     * and with a list of old and new values.
     *
     * @param source
     *         the event source.
     * @param changedObject
     *         the {@code ManagedObject} whose value is changed.
     * @param index
     *         the instance OID of the changed instance (i.e. row index).
     * @param modification
     *         identifies the type of modification that triggered the event.
     * @since 3.0
     */
    public MOChangeEvent(Object source, ManagedObject<SubRequest<?>> changedObject,
                         OID index, Modification modification) {
        super(source, false);
        this.changedObject = changedObject;
        this.oid = index;
        this.modification = modification;
        this.oidType = OidType.index;
    }

    /**
     * Creates a deniable {@code MOChangeEvent} object based on the changed
     * managed object instances that are identified through a common the instance OID (i.e. their row index)
     * and with a list of old and new values.
     *
     * @param source
     *         the event source.
     * @param changedObject
     *         the {@code ManagedObject} whose value is changed.
     * @param index
     *         the instance OID of the changed instance (i.e. row index).
     * @param modification
     *         identifies the type of modification that triggered the event.
     * @param subRequest
     *         the subRequest that triggered the change. This might by {@code null} if the change was not triggered by
     *         a SNMP, AgentX, or similar external request or if the request cannot be identified through the call
     *         hierarchy.
     * @since 3.2.3
     */
    public MOChangeEvent(Object source, ManagedObject<SubRequest<?>> changedObject,
                         OID index, Modification modification, SubRequest<?> subRequest) {
        this(source, changedObject, index, modification);
        this.subRequest = subRequest;
    }

    /**
     * Creates a {@code MOChangeEvent} object based on the changed managed
     * object, the instance OID of the changed value, with old and new value.
     *
     * @param source
     *         the event source.
     * @param changedObject
     *         the {@code ManagedObject} whose value is changed.
     * @param oid
     *         the instance OID of the changed instance.
     * @param oldValue
     *         the old value.
     * @param newValue
     *         the new value.
     * @param deniable
     *         indicates whether the event can be canceled through setting its
     *         denyReason member to a SNMP error status.
     * @since 1.1
     */
    public MOChangeEvent(Object source, ManagedObject<SubRequest<?>> changedObject,
                         OID oid, Variable oldValue, Variable newValue, boolean deniable) {
        super(source, deniable);
        this.changedObject = changedObject;
        this.oid = oid;
        this.oldValue = oldValue;
        this.newValue = newValue;
        this.modification = getModificationFromValues(oldValue, newValue);
        this.oidType = OidType.fullyQualified;
    }

    /**
     * Creates a {@code MOChangeEvent} object based on the changed managed
     * object, the instance OID of the changed value, with old and new value.
     *
     * @param source
     *         the event source.
     * @param changedObject
     *         the {@code ManagedObject} whose value is changed.
     * @param oid
     *         the instance OID of the changed instance.
     * @param oldValue
     *         the old value.
     * @param newValue
     *         the new value.
     * @param deniable
     *         indicates whether the event can be canceled through setting its
     *         denyReason member to a SNMP error status.
     * @param subRequest
     *         the subRequest that triggered the change. This might by {@code null} if the change was not triggered by
     *         a SNMP, AgentX, or similar external request.
     * @since 3.2.3
     */
    public MOChangeEvent(Object source, ManagedObject<SubRequest<?>> changedObject,
                         OID oid, Variable oldValue, Variable newValue, boolean deniable, SubRequest<?> subRequest) {
        this(source, changedObject, oid, oldValue, newValue, deniable);
        this.subRequest = subRequest;
    }

    public ManagedObject<SubRequest<?>> getChangedObject() {
        return changedObject;
    }

    public OID getOID() {
        return oid;
    }

    public Variable getOldValue() {
        return oldValue;
    }

    public Variable getNewValue() {
        return newValue;
    }

    /**
     * Gets the type of the modification. This could be implicitly determined by
     * {@link #getModificationFromValues(Variable, Variable)} object construction or explicitly set by a suitable
     * constructor.
     *
     * @return
     *    a modification type as defined by {@link Modification}.
     * @since 3.0
     */
    public Modification getModification() {
        return modification;
    }

    /**
     * Gets the representation type of the OID of the event as defined by {@link OidType}.
     * The type {@link OidType#index} refers to the row index of a {@link MOTable} {@link ManagedObject}.
     * All other types refer to a single instance OID, whereas {@link OidType#fullyQualified} includes the {@link OID}
     * of the {@link ManagedObject} and {@link OidType#instanceSuffix} does not.
     *
     * @return
     *    the type of the OID returned by {@link #getOID()}.
     * @since 3.0
     */
    public OidType getOidType() {
        return oidType;
    }

    /**
     * Get the {@link SubRequest} that triggered this change. If {@code null} there is either no SNMP or AgentX request
     * that triggered this change or the request cannot be identified.
     * @return
     *     the {@link SubRequest} that triggered this change or {@code null} if that is not known.
     * @since 3.2.3
     */
    public SubRequest<?> getSubRequest() {
        return subRequest;
    }

    @Override
    public String toString() {
        return "MOChangeEvent{" +
                "changedObject=" + changedObject +
                ", oid=" + oid +
                ", oldValue=" + oldValue +
                ", newValue=" + newValue +
                ", modification=" + modification +
                ", oidType=" + oidType +
                ", subRequest=" + subRequest +
                '}';
    }
}
