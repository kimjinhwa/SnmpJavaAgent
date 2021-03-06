/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - NotificationLogListener.java  
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

import org.snmp4j.smi.Address;

import java.util.*;

/**
 * A <code>NotificationLogListener</code> processes notification logging events.
 * @author Frank Fock
 * @version 1.4
 * @since 1.4
 */
public interface NotificationLogListener extends EventListener {

  /**
   * Process a notification log event.
   * @param notificationLogEvent
   *    a NotificationLogEvent instance describing a notification.
   * @param <A> type of the peer {@link Address}.
   */
  <A extends Address> void notificationLogEvent(NotificationLogEvent<A> notificationLogEvent);

}
