/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - RandomAccessManagedObject.java  
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

package org.snmp4j.agent;

import org.snmp4j.agent.io.ImportMode;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.VariableBinding;

import java.util.Iterator;
import java.util.List;

/**
 * A random access managed object allows to import and export any instance of a {@link ManagedObject} to/from
 * a byte array. What forms an instance (a single {@link org.snmp4j.smi.Variable} or a set of those) depends
 * on the particular {@link ManagedObject} implementation but have to be consistent across all method implementation
 * of this interface.
 *
 * @author Frank Fock
 * @version 3.2.0
 */
public interface RandomAccessManagedObject<SR extends SubRequest<?>> extends ManagedObject<SR> {

    /**
     * Imports the data that internally represents the instance specified by the OID suffix {@code instanceID}
     * from the byte data provided which can be encoded in any representation the {@link ManagedObject} is able to
     * understand.
     * @param instanceSubID
     *    the OID suffix identifying the instance to export, for scalars this is "0" and for tabular objects
     *    this is the row index.
     * @param data
     *    the SNMP data of the instance where the OID identifies the sub-instance (i.e. the column sub-ID for row
     *    instances and "0" for scalar objects).
     * @param importMode
     *    defines the import strategy - must not be {@code null}!
     * @return
     *    {@code true} if the import was successful, {@code false} otherwise.
     */
    boolean importInstance(OID instanceSubID, List<VariableBinding> data, ImportMode importMode);

    /**
     * Exports the byte representation of an instance of the {@link ManagedObject}.
     * @param instanceSubID
     *    the OID suffix identifying the instance to export, for scalars this is "0" and for tabular objects
     *    this is the row index.
     * @return
     *    the SNMP data of the instance where the OID identifies the sub-instance (i.e. the column sub-ID for row
     *    instances and "0" for scalar objects).
     */
    List<VariableBinding> exportInstance(OID instanceSubID);

    /**
     * Tests if the specified instance should be serialized or deserialized through
     * persistent storage load or save operation.
     * @param instanceSubID
     *    the OID suffix identifying the instance to check, for scalars this is "0" and for tabular objects
     *    this is the row index.
     * @return
     *    {@code true} if the specified sub-instance exists and is
     *    {@link org.snmp4j.agent.mo.snmp.StorageType#volatile_}.
     * @since 3.2.0
     */
    default boolean isVolatile(OID instanceSubID) {
        return isVolatile();
    }

    Iterator<OID> instanceIterator();

    /**
     * Returns the number of instances managed by this {@link ManagedObject}.
     * @return
     *    the number of instances managed by this object.
     */
    int instanceCount();

    /**
     * Tests if this instance of a SerializableManagedObject should be
     * serialized or deserialized through persistent storage
     * load or save operation.
     * @return
     *    {@code true} if persistent storage operations should ignore this {@link ManagedObject} and {@code false}
     *    if this object should be saved/loaded to/from persistent storage.
     */
    boolean isVolatile();

    /**
     * Returns the instance sub-identifier suffix for the given instance OID. Any implementations of this method
     * must use the same instance notion of instance identifier as {@link #importInstance(OID, List, ImportMode)},
     * {@link #exportInstance(OID)}, and {@link #instanceIterator()}.
     *
     * @param instanceOID
     *    the fully qualified {@link OID} of a SNMP {@link org.snmp4j.smi.Variable}.
     * @return
     *    the instance ID that uniquely identifies the object instance the specified {@link org.snmp4j.smi.Variable}
     *    belongs to within this {@link RandomAccessManagedObject}.
     */
    default OID getInstanceSubID(OID instanceOID) {
        OID objectTypeOID = getScope().getLowerBound();
        return instanceOID.getSuffix(objectTypeOID);
    }

}
