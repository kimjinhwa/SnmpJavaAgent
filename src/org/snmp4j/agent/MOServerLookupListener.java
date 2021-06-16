/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOServerLookupListener.java  
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

import java.util.*;

/**
 * An object that is interested in callback notifications of lookup events
 * on a {@code MOServer} instance has to implement the
 * {@code MOServerLookupListener} interface.
 *
 * @author Frank Fock
 * @version 3.0.4
 */
public interface MOServerLookupListener extends EventListener {

    /**
     * A {@link MOServer} instance has looked up a managed object for which the
     * listener has been registered.
     *
     * @param event
     *         a {@code MOServerLookupEvent} describing the lookup query and the
     *         managed object that has been looked up.
     */
    void lookupEvent(MOServerLookupEvent event);

    /**
     * A {@link MOServer} instance is about to check if the managed object for
     * which the listener had been registered matches a query. A managed object
     * with dynamic content like a non-static table might use this event to
     * update its content.
     *
     * @param event
     *         a {@code MOServerLookupEvent} describing the lookup query and the
     *         managed object that is to be queried.
     */
    void queryEvent(MOServerLookupEvent event);

    /**
     * A {@link MOServer} instance has finished the intended use for which {@link #lookupEvent(MOServerLookupEvent)} has
     * been called previously. By default this method is a no-op. It can be implemented to trigger statistics for GET,
     * GETNEXT, and GETBULK requests as well as to trigger further instrumentation update routines on SET requests.
     *
     * @param event
     *         the same instance {@link MOServerLookupEvent} provided during lookup but after the intended use has been
     *         finished. Note: the lookup event firing instance is responsible to call this method when the intended use
     *         is finished. There is no guarantee that this will happen for all intended uses (this is particularly true
     *         for {@link MOServerLookupEvent.IntendedUse#undefined}).
     * @param result
     *         The {@link SubRequest} or other objects like {@link org.snmp4j.smi.VariableBinding}
     *         which triggered the lookup and/or are actually modified by the completed use (i.e., lookup result).
     */
    default void completedUse(MOServerLookupEvent event, Object result) {
        // nothing to do
    }

}
