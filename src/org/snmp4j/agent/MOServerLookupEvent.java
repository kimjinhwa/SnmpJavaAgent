/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOServerLookupEvent.java  
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

import org.snmp4j.agent.request.SubRequest;

import java.util.ArrayList;
import java.util.EventObject;
import java.util.List;

/**
 * A {@code MOServerLookupEvent} describes a lookup of a managed object within a {@link MOServer} repository. Such an
 * event can be used to update {@link ManagedObject}s before they are accessed and processed by a command responder
 * (agent).
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public class MOServerLookupEvent extends EventObject {

    private static final long serialVersionUID = -6148932595537688122L;

    public enum IntendedUse {
        undefined, register, get, getNext, prepare, commit, undo, cleanUp, update, unregister
    }

    ;

    private ManagedObject<?> lookupResult;
    private MOQuery query;
    private IntendedUse intendedUse;
    private List<MOServerLookupListener> completionListeners;

    public MOServerLookupEvent(Object source, ManagedObject<?> lookupResult, MOQuery query, IntendedUse intendedUse) {
        super(source);
        this.lookupResult = lookupResult;
        this.query = query;
        this.intendedUse = intendedUse;
    }

    public MOServerLookupEvent(Object source, ManagedObject<?> lookupResult,
                               MOQuery query, IntendedUse intendedUse, boolean withCompletionCallback) {
        this(source, lookupResult, query, intendedUse);
        if (withCompletionCallback) {
            this.completionListeners = new ArrayList<>(2);
        }
    }

    /**
     * Returns the {@code ManagedObject} that has been looked up.
     *
     * @return a {@code ManagedObject}.
     */
    public ManagedObject<?> getLookupResult() {
        return lookupResult;
    }

    /**
     * Sets the lookup result after construction, for example, if the value is not yet known at construction time.
     *
     * @param lookupResult
     *         a managed object that has been looked up by a {@link MOServer}.
     *
     * @since 3.0
     */
    public void setLookupResult(ManagedObject<?> lookupResult) {
        this.lookupResult = lookupResult;
    }

    /**
     * Returns the query that has been used to lookup the managed object.
     *
     * @return a {@code MOQuery} instance that triggered the event.
     */
    public MOQuery getQuery() {
        return query;
    }

    /**
     * Returns the intended use that triggered the lookup event.
     *
     * @return the intended use or {@link IntendedUse#undefined} if there is no information available about the intended
     * use of the lookup results.
     * @since 3.0
     */
    public IntendedUse getIntendedUse() {
        return intendedUse;
    }

    public boolean isCompletionCallbackAvailable() {
        return completionListeners != null;
    }

    public synchronized boolean addCompletionListener(MOServerLookupListener lookupCompletionListener) {
        if (this.completionListeners == null) {
            return false;
        }
        this.completionListeners.add(lookupCompletionListener);
        return true;
    }

    public synchronized boolean removeCompletionListener(MOServerLookupListener lookupCompletionListener) {
        return this.completionListeners != null && this.completionListeners.remove(lookupCompletionListener);
    }

    public synchronized void completedUse(Object result) {
        if (this.completionListeners != null) {
            for (MOServerLookupListener listener : completionListeners) {
                listener.completedUse(this, result);
            }
        }
    }
}
