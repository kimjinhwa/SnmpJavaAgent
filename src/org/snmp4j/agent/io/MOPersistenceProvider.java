/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOPersistenceProvider.java  
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

package org.snmp4j.agent.io;

import org.snmp4j.agent.mo.MOPriorityProvider;
import org.snmp4j.smi.OctetString;

import java.io.IOException;

/**
 * The {@code MOPersistenceProvider} interface defines how persistent
 * storage can be used to save and restore an agents state. The interface
 * intentionally does not define how the persistence provider gets access
 * to the agent's state.
 *
 * @author Frank Fock
 * @version 3.5.0
 */
public interface MOPersistenceProvider {

    /**
     * Restore (load) agent state from the specified URI (can be as simple as
     * a file path).
     * @param uri
     *    a string pointing to the persistent storage from which the agent state
     *    should be restored from. The format of he string is specified by the
     *    persistence provider. A {@code null} value can be specified to
     *    let the persistence provider use its default URI. If that default URI
     *    is {@code null} too, a {@code NullPointerException} will be
     *    thrown.
     * @param importMode
     *    specifies how the agent's current state should be update while
     *    restoring a previous state.
     * @throws IOException
     *    if the restore operation fails.
     * @since 1.2
     */
    void restore(String uri, int importMode) throws IOException;

    /**
     * Restore (load) agent state from the specified URI (can be as simple as a file path).
     *
     * @param uri
     *         a string pointing to the persistent storage from which the agent state should be restored from. The
     *         format of he string is specified by the persistence provider. A {@code null} value can be specified to
     *         let the persistence provider use its default URI. If that default URI is {@code null} too, a {@code
     *         NullPointerException} will be thrown.
     * @param importMode
     *         specifies how the agent's current state should be update while restoring a previous state.
     * @param priorityProvider
     *         provides the boot managed object and its priority map that defines the order of restoring
     *         all other managed objects.
     * @throws IOException
     *         if the restore operation fails.
     * @since 3.5.0
     */
    default void restore(String uri, int importMode, MOPriorityProvider priorityProvider) throws IOException {
        restore(uri, importMode);
    }

    /**
     * Stores the current agent state to persistent storage specified by the
     * supplied URI.
     * @param uri
     *    a string pointing to the persistent storage from which the agent state
     *    should be restored from. The format of the string is specified by the
     *    persistence provider. A {@code null} value can be specified to
     *    let the persistence provider use its default URI. If that default URI
     *    is {@code null} too, a {@code NullPointerException} will be
     *    thrown.
     * @throws IOException
     *    if the store operation fails.
     * @since 1.2
     */
    void store(String uri) throws IOException;

    /**
     * Stores the current agent state to persistent storage specified by the supplied URI in the order defined by
     * the given {@link MOPriorityProvider#getPriorityMap(OctetString)}.
     *
     * @param uri
     *         a string pointing to the persistent storage from which the agent state should be restored from. The
     *         format of the string is specified by the persistence provider. A {@code null} value can be specified to
     *         let the persistence provider use its default URI. If that default URI is {@code null} too, a {@code
     *         NullPointerException} will be thrown.
     * @param priorityProvider
     *         provides the boot managed object and its priority map that defines the order of storing
     *         all other managed objects.
     *
     * @throws IOException
     *         if the store operation fails.
     * @since 3.5.0
     */
    void store(String uri, MOPriorityProvider priorityProvider) throws IOException;

    /**
     * Checks whether the supplied URI string is valid for this persistence
     * provider.
     * @param uri
     *    a string identifying a persistent storage location for this storage
     *    provider.
     * @return
     *    {@code true} if the {@code uri} is valid, {@code false}
     *    otherwise.
     * @since 1.2
     */
    boolean isValidPersistenceURI(String uri);

    /**
     * Returns an unique ID of the persistence provider which should identify the
     * format and type of the persistence provider.
     * @return
     *    an 1-32 character long string that identifies the persistence provider.
     * @since 1.2
     */
    String getPersistenceProviderID();

    /**
     * Gets the URI of the default persistent storage for this provider.
     * @return
     *    the URI (e.g. file path) for the default persistent storage location of
     *    this provider. A provider may use a different one. A {@code null}
     *    value indicates that there is no default location.
     */
    String getDefaultURI();
}
