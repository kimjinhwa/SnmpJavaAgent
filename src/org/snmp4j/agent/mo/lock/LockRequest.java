/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - LockRequest.java  
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
package org.snmp4j.agent.mo.lock;

import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.request.SubRequest;

/**
 * The <code>LockRequest</code> class bundles information necessary to request a lock on a
 * {@link org.snmp4j.agent.ManagedObject} for update or value access.
 *
 * @author Frank Fock
 * @since 2.4.0
 */
public class LockRequest {

  public enum LockStatus {
    /** Indicates that no locking was required based on the active {@link MOLockStrategy}.*/
    notRequired,
    /** The lock has been acquired successfully (lock operation).*/
    locked,
    /**
     * The lock has been acquired successfully, but after a lock timed out for a better matching {@link ManagedObject}
     * (lock operation).
     */
    lockedAfterTimeout,
    /** The lock has been released successfully (unlock operation).*/
    unlocked,
    /** The lock could not be acquired within the timeoutMillis.*/
    lockTimedOut
  }

  /** The owner of the lock, must be not <code>null</code> (otherwise no lock can be acquired).*/
  private Object lockOwner;
  /**
   * The number of 1/1000 seconds to wait for a lock. If timeout occurs, the target managed object will be handled
   * as if it does not exist.
   */
  private long timeoutMillis;

  /** Returns the information about the status of the lock request. Initially this attribute is <code>value</code>.*/
  private LockStatus lockRequestStatus;

  /**
   * Creates a new lock request with owner and timeout.
   * @param lockOwner
   *    the owner of the lock. The same owner may lock a managed object again
   *    (recursively), see {@link org.snmp4j.agent.MOServer#lock(Object, ManagedObject)} for details.
   * @param timeoutMillis
   *    the number of 1/1000 seconds to wait for the lock. 0 or less disables
   *    the timeout and waits forever until the lock is released by the current owner.
   */
  public LockRequest(Object lockOwner, long timeoutMillis) {
    this.lockOwner = lockOwner;
    this.timeoutMillis = timeoutMillis;
  }

  public Object getLockOwner() {
    return lockOwner;
  }

  public long getTimeoutMillis() {
    return timeoutMillis;
  }

  public LockStatus getLockRequestStatus() {
    return lockRequestStatus;
  }

  public void setLockRequestStatus(LockStatus lockRequestStatus) {
    this.lockRequestStatus = lockRequestStatus;
  }
}
