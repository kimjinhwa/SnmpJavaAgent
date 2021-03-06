/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - AgentStateListener.java  
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

/**
 * The {@link AgentStateListener} informs about changes of the state of a SNMP agent. According to the state change,
 * the listener may register or unregister MIB modules or run other tasks.
 * @param ACM
 *    a {@link AgentConfigManager} for example or any other object firing {@link AgentState} events.
 *
 * @author Frank Fock
 * @version 3.0
 * @since 3.0
 */
public interface AgentStateListener<ACM> {

    /**
     * The agent state has changed to the new state as provided.
     * @param agentConfigManager
     *    the agent's configuration manager. Use this object to access all agent resources, if needed to process this
     *    event.
     * @param newState
     *    the new state of the agent. Although the listener may advance to agent state further, it is not recommended
     *    to do so, because the {@link AgentConfigManager} will do it anyway.
     */
    void agentStateChanged(ACM agentConfigManager, AgentState newState);
}
