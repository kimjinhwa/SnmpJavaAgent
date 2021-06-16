/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - ManagedObject.java  
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

import org.snmp4j.smi.OID;
import org.snmp4j.agent.request.SubRequest;

/**
 * The {@code ManagedObject} interface defines the basic operations
 * for all SNMP4J manageable objects.
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public interface ManagedObject<SR extends SubRequest<?>> {

    /**
     * Returns the scope of object identifiers this managed object is managing.
     *
     * @return the {@code MOScope} that defines a range (possibly also a single
     * or none instance OID) of object IDs managed by this managed object.
     */
    MOScope getScope();

    /**
     * Finds the first object ID (OID) in the specified search range.
     *
     * @param range
     *         the {@code MOScope} for the search.
     *
     * @return the {@code OID} that is included in the search {@code range}
     * and {@code null} if no such instances could be found.
     */
    OID find(MOScope range);

    /**
     * Processes a GET request and return the result in the supplied sub-request.
     *
     * @param request
     *         the {@code SubRequest} to process.
     */
    void get(SR request);

    /**
     * Finds the successor instance for the object instance ID (OID) given
     * by the supplied sub-request and returns it within the supplied sub-request
     * object.
     *
     * @param request
     *         the {@code SubRequest} to process.
     *
     * @return {@code true} if the search request found an appropriate instance,
     * {@code false} otherwise.
     */
    boolean next(SR request);

    /**
     * Prepares a SET (sub)request. This method represents the first phase of a
     * two phase commit. During preparation all necessary resources should be
     * locked in order to be able to execute the commit without claiming
     * additional resources.
     *
     * @param request
     *         the {@code SubRequest} to process.
     */
    void prepare(SR request);

    /**
     * Commits a previously prepared SET (sub)request. This is the second phase
     * of a two phase commit. The change is committed but the resources locked
     * during prepare not freed yet.
     *
     * @param request
     *         the {@code SubRequest} to process.
     */
    void commit(SR request);

    /**
     * Compensates (undo) a (sub)request when a commit of another subrequest
     * failed with an error. This also frees any resources locked during
     * the preparation phase.
     *
     * @param request
     *         the {@code SubRequest} to process.
     */
    void undo(SR request);

    /**
     * Cleansup a (sub)request and frees all resources locked during
     * the preparation phase.
     *
     * @param request
     *         the {@code SubRequest} to process.
     */
    void cleanup(SR request);

}
