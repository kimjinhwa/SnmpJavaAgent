/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - AgentState.java  
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

import java.util.List;

/**
 * The {@link AgentState} interface provides information about the state of a SNMP agent.
 * States are represented by integer values. This allows implementing classes to extend
 * states supported by an agent.
 *
 * @author Frank Fock
 * @version 3.0.2
 * @since 3.0
 */
public interface AgentState {

    int STATE_CREATED = 0;
    int STATE_INITIALIZED = 10;
    int STATE_CONFIGURED = 20;
    int STATE_RESTORED = 30;
    int STATE_SUSPENDED = 35;
    int STATE_RUNNING = 40;
    int STATE_SAVED = 50;
    int STATE_SHUTDOWN = -1;

    /**
     * Gets the current state of the agent.
     * @return
     *    an integer representing the current state. See {@link #STATE_CREATED}.
     */
    int getState();

    /**
     * Sets the new state independent from the current state.
     *
     * @param newState
     *         the new state.
     */
    void setState(int newState);

    /**
     * Advance the state to the given state. If the current state is greater than
     * the provided state, the current state will not be changed.
     *
     * @param newState the new minimum state.
     */
    void advanceState(int newState);

    /**
     * Add an error description to the internal error list.
     *
     * @param error
     *         an ErrorDescriptor instance to add.
     */
    void addError(ErrorDescriptor error);

    /**
     * Get the error descriptors associated with this agent state.
     *
     * @return the errors descriptor list.
     */
    List<ErrorDescriptor> getErrors();


    interface ErrorDescriptor {
        String getDescription();

        int getSourceState();

        int getTargetState();

        Exception getException();
    }
}
