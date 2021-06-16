/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOServer.java  
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

import org.snmp4j.agent.mo.MOFilter;
import org.snmp4j.agent.mo.lock.LockRequest;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.smi.OctetString;

import java.util.*;

/**
 * The managed object server interface defines the services that a repository
 * of managed objects needs to provide for a command responder.
 *
 * @author Frank Fock
 * @version 3.5.0
 */
public interface MOServer {

    /**
     * Adds a context listener to the server. The listener will be informed about
     * context insertion and removal.
     *
     * @param listener
     *         a {@code ContextListener} instance to be informed about context
     *         changes.
     */
    void addContextListener(ContextListener listener);

    /**
     * Removes a previously added context listener.
     *
     * @param listener
     *         a {@code ContextListener} instance.
     */
    void removeContextListener(ContextListener listener);

    /**
     * Adds the supplied context to the server. The server however may silently
     * ignore the request if local constraints do not allow to add the context
     * (although this should be an exception case only).
     *
     * @param context
     *         an {@code OctetString} representing the context name to add.
     */
    void addContext(OctetString context);

    /**
     * Removes a context from the server. Removing a context does not remove
     * any managed objects from the server's registry.
     *
     * @param context
     *         n {@code OctetString} representing the context name to remove.
     */
    void removeContext(OctetString context);

    /**
     * Registers a managed object for the specified context. A managed object can
     * be registered for more than one context.
     *
     * @param mo
     *         a {@code ManagedObject} instance.
     * @param context
     *         the context name for which to register the {@code mo} or
     *         {@code null} if the managed oject is to be registered for all
     *         contexts (including the default context).
     *
     * @throws DuplicateRegistrationException
     *         if the registration conflicts (i.e. overlaps) with an already existing
     *         registration.
     */
    void register(ManagedObject<?> mo, OctetString context)
            throws DuplicateRegistrationException;

    /**
     * Registers a managed object for the specified context if it has not been registered already (otherwise it does
     * nothing but returning {@code false}. A managed object can be registered for more than one context.
     *
     * @param mo
     *         a {@code ManagedObject} instance.
     * @param context
     *         the context name for which to register the {@code mo} or
     *         {@code null} if the managed oject is to be registered for all
     *         contexts (including the default context).
     *
     * @return {@code} if the registration was successful and {@code false} if it overlaps with an already existing
     *         registration.
     * @since 3.0.2
     */
    default boolean registerNew(ManagedObject<?> mo, OctetString context) {
        try {
            register(mo, context);
            return true;
        } catch (DuplicateRegistrationException drex) {
            return false;
        }
    }

    /**
     * Removes the registration of the supplied managed object for the specified
     * context.
     *
     * @param mo
     *         a {@code ManagedObject} instance.
     * @param context
     *         the context name for which to unregister the {@code mo} or
     *         {@code null} if the managed object is to be unregistered for all
     *         contexts (including the default context). In the latter case however,
     *         explicit registrations for a particular context will not be removed!
     *
     * @return the removed {@link ManagedObject}instance or {@code null} if
     * the removal failed.
     */
    ManagedObject<?> unregister(ManagedObject<?> mo, OctetString context);


    /**
     * Return an {@link Iterator} on the registered {@link ManagedObject}s of this server in order defined
     * by the given comparator.
     * @param comparator
     *    the comparator that defines the order of the managed objects to be returned.
     * @return
     *    the iterator a copy of the registry.
     * @since 3.5.0
     */
    default Iterator<Map.Entry<MOScope, ManagedObject<?>>> iterator(Comparator<MOScope> comparator) {
        return iterator(comparator, null);
    }

    /**
     * Return an {@link Iterator} on the registered {@link ManagedObject}s of this server in order defined
     * by the given comparator and filtered.
     * @param comparator
     *    the comparator that defines the order of the managed objects to be returned.
     * @param moFilter
     *    if not {@code null}, only those managed objects are returned by this iterator
     *    that pass the specified filter.
     * @return
     *    the iterator a copy of the registry.
     * @since 3.5.0
     */
    Iterator<Map.Entry<MOScope, ManagedObject<?>>> iterator(Comparator<MOScope> comparator, MOFilter moFilter);

    /**
     * Adds a managed object lookup listener for the supplied managed object to
     * this managed object server. A {@code MOServerLookupListener} is called
     * before the managed object is returned by {@link #lookup(MOQuery query)}.
     *
     * @param listener
     *         a {@code MOServerLookupListener} instance, for example a managed
     *         object that needs to update its state whenever it has been looked up
     * @param mo
     *         the {@code ManagedObject} that triggers the
     *         {@link MOServerLookupEvent} to be fired when it has been looked up.
     */
    void addLookupListener(MOServerLookupListener listener, ManagedObject<?> mo);

    /**
     * Removes a managed object lookup listener for the specified managed object.
     *
     * @param listener
     *         a {@code MOServerLookupListener} instance.
     * @param mo
     *         the {@code ManagedObject} that triggered the
     *         {@link MOServerLookupEvent} to be fired when it has been looked up.
     *
     * @return {@code true} if the listener could be removed or {@code false}
     * if such a listener is not registered.
     */
    boolean removeLookupListener(MOServerLookupListener listener, ManagedObject<?> mo);

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query. No locking will be performed, regardless of the
     * set {@link org.snmp4j.agent.mo.lock.MOLockStrategy}.
     *
     * @param query
     *         a {@code MOQuery} instance.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     */
    default ManagedObject<?> lookup(MOQuery query) {
        return lookup(query, null,
                new MOServerLookupEvent(this, null, query, MOServerLookupEvent.IntendedUse.undefined),
                ManagedObject.class);
    }

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query. No locking will be performed, regardless of the
     * set {@link org.snmp4j.agent.mo.lock.MOLockStrategy}.
     *
     * @param query
     *         a {@code MOQuery} instance.
     * @param managedObjectType
     *         the {@link ManagedObject} implementation class that is supported by the caller. Use
     *         {@link ManagedObject} by default.
     * @param <MO> the {@link ManagedObject} type to lookup.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     * @since 3.1.0
     */
    default <MO extends ManagedObject<?>> MO lookup(MOQuery query, Class<MO> managedObjectType) {
        return lookup(query, null,
                new MOServerLookupEvent(this, null, query, MOServerLookupEvent.IntendedUse.undefined),
                managedObjectType);
    }

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query. Locking will be performed according to the
     * set {@link org.snmp4j.agent.mo.lock.MOLockStrategy} before the lookup
     * listener is fired.
     * {@link MOServerLookupEvent}s fired on behalf of this method call will
     * report the request processing phase {@link MOServerLookupEvent.IntendedUse#undefined}.
     * To accurately report the phase use {@link #lookup(MOQuery, LockRequest, MOServerLookupEvent)} instead.
     * CAUTION: To make sure that the acquired lock is released after the
     * using of the managed object has been finished, the {@link #unlock(Object, ManagedObject)}
     * method must be called then.
     *
     * @param query
     *         a {@code MOQuery} instance.
     * @param lockRequest
     *         the {@link LockRequest} that holds the lock owner and the timeout for
     *         acquiring a lock and returns whether a lock has been acquired or not
     *         on behalf of this lookup operation.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     * @since 2.4.0
     * @deprecated Use {@link #lookup(MOQuery, LockRequest, MOServerLookupEvent, Class)} instead to specify
     * the intended use, and event source.
     */
    @Deprecated
    default ManagedObject<?> lookup(MOQuery query, LockRequest lockRequest) {
        return lookup(query, lockRequest, new MOServerLookupEvent(this, null, query,
                MOServerLookupEvent.IntendedUse.undefined));
    }

    ;

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query. Locking will be performed according to the
     * set {@link org.snmp4j.agent.mo.lock.MOLockStrategy} before the lookup
     * listener is fired.
     * CAUTION: To make sure that the acquired lock is released after the
     * using of the managed object has been finished, the {@link #unlock(Object, ManagedObject)}
     * method must be called then.
     *
     * @param query
     *         a {@code MOQuery} instance.
     * @param lockRequest
     *         the {@link LockRequest} that holds the lock owner and the timeout for
     *         acquiring a lock and returns whether a lock has been acquired or not
     *         on behalf of this lookup operation.
     * @param lookupEvent
     *         provides additional information about the intended use and optionally a callback to be informed about
     *         the completion of the use, including a reference to its result.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     * @since 3.0
     */
    default ManagedObject<?> lookup(MOQuery query, LockRequest lockRequest, MOServerLookupEvent lookupEvent) {
        return lookup(query, lockRequest, lookupEvent, ManagedObject.class);
    }

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query and implements the given {@link ManagedObject} class.
     * Locking will be performed according to the set {@link org.snmp4j.agent.mo.lock.MOLockStrategy} before the lookup
     * listener is fired.
     * CAUTION: To make sure that the acquired lock is released after the
     * using of the managed object has been finished, the {@link #unlock(Object, ManagedObject)}
     * method must be called then.
     *
     * @param query
     *         a {@code MOQuery} instance.
     * @param lockRequest
     *         the {@link LockRequest} that holds the lock owner and the timeout for
     *         acquiring a lock and returns whether a lock has been acquired or not
     *         on behalf of this lookup operation.
     * @param lookupEvent
     *         provides additional information about the intended use and optionally a callback to be informed about
     *         the completion of the use, including a reference to its result.
     * @param managedObjectType
     *         the {@link ManagedObject} implementation class that is supported by the caller. Use
     *         {@link ManagedObject} by default.
     * @param <MO> the {@link ManagedObject} type to lookup.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     * @since 3.1
     */
    <MO extends ManagedObject<?>> MO
            lookup(MOQuery query, LockRequest lockRequest, MOServerLookupEvent lookupEvent, Class<MO> managedObjectType);

    /**
     * Return a read-only {@code Iterator} over the content of this server.
     * The iterator is thread safe and can be used while the server is being
     * modified. The remove operation of the iterator is not supported.
     *
     * @return the {@code Iterator} on the Map.Entry instances managed by
     * this server. Each {@code Entry} consists of an {@link MOScope}
     * key instance and a corresponding {@link ManagedObject} value instance.
     * If the {@code ManagedObject} has been registered for a specific
     * context, then a {@link MOContextScope} is returned as key, otherwise
     * the managed objects own {@code MOScope} is returned.
     */
    Iterator<Map.Entry<MOScope, ManagedObject<?>>> iterator();

    /**
     * Locks a ManagedObject by the supplied owner. Once a ManagedObject is
     * locked, a lookup attempt will block until it is unlocked or a predefined
     * timeout occurs.
     *
     * @param owner
     *         an Object.
     * @param managedObject
     *         the ManagedObject to lock.
     *
     * @return {@code true} if the lock could be acquired, {@code false}
     * otherwise, i.e. if an InterruptedException has occurred.
     */
    boolean lock(Object owner, ManagedObject<?> managedObject);

    /**
     * Locks a ManagedObject by the supplied owner. Once a ManagedObject is
     * locked, a lookup attempt will block until it is unlocked or a predefined
     * timeout occurs.
     *
     * @param owner
     *         an Object.
     * @param managedObject
     *         the ManagedObject to lock.
     * @param timeoutMillis
     *         the number of 1/1000 seconds to wait for the lock. 0 or less disables
     *         the timeout and waits forever until the lock is released by the current owner.
     *
     * @return {@code true} if the lock could be acquired, {@code false}
     * otherwise, i.e. if an InterruptedException or timeout has occurred.
     * @since 1.3
     */
    boolean lock(Object owner, ManagedObject<?> managedObject, long timeoutMillis);

    /**
     * Unlocks a ManagedObject that has been locked by the specified owner. If
     * the ManagedObject is currently locked by another owner this method returns
     * silently.
     * <p>
     * Note: In debug log mode a message is locked if the lock owner does not
     * match the current lock owner.
     *
     * @param owner
     *         an Object.
     * @param managedObject
     *         the ManagedObject to unlock. If {@code managedObject} is {@code null}
     *         then this call has no effect.
     *
     * @return {@code true} if the lock has been found and released successfully,
     * {@code false} otherwise.
     */
    boolean unlock(Object owner, ManagedObject<?> managedObject);

    /**
     * Returns the contexts known by the server.
     *
     * @return an array of context names.
     */
    OctetString[] getContexts();

    /**
     * Checks whether the supplied context is supported (registered) by this
     * server.
     *
     * @param context
     *         a context name.
     *
     * @return {@code true} if the context is support (thus has previously added
     * by {@link #addContext}) and {@code false} otherwise.
     */
    boolean isContextSupported(OctetString context);

    /**
     * Returns the contexts for which the supplied {@link ManagedObject} has been
     * registered.
     *
     * @param managedObject
     *         a {@link ManagedObject} instance.
     *
     * @return an array of context strings, for which {@code managedObject} has
     * been registered. If the {@code managedObject} has been registered
     * for all contexts, a {@code null} element is included in the array.
     * @since 1.4
     */
    OctetString[] getRegisteredContexts(ManagedObject<?> managedObject);

    /**
     * Returns the scopes {@link MOScope} or {@link MOContextScope} for which the supplied {@link ManagedObject}
     * has been registered in a map indexed by context.
     * @param managedObject
     *         a {@link ManagedObject} instance.
     * @return a possibly empty map of context to {@link MOScope} entries. A registration to the default
     * ("one-registration-for-all-contexts") {@code null} context is returned with a {@code null} context key
     * value.
     * @since 3.5.0
     */
    Map<OctetString, MOScope> getRegisteredScopes(ManagedObject<?> managedObject);
}
