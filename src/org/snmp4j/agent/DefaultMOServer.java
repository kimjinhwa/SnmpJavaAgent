/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DefaultMOServer.java  
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

import java.util.*;
import java.util.Map.Entry;

import org.snmp4j.agent.mo.*;
import org.snmp4j.agent.mo.lock.DefaultMOLockStrategy;
import org.snmp4j.agent.mo.lock.LockRequest;
import org.snmp4j.agent.mo.lock.MOLockStrategy;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.log.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;

/**
 * The default MO server implementation uses a sorted map for the managed object
 * registry.
 *
 * @author Frank Fock
 * @version 3.1.0
 */
public class DefaultMOServer implements MOServer {

    private static final LogAdapter logger =
            LogFactory.getLogger(DefaultMOServer.class);

    private final Set<OctetString> contexts;
    private final SortedMap<MOScope, ManagedObject<?>> registry;
    private final Map<ManagedObject<?>, Lock> lockList;
    private Map<ManagedObject<?>, List<MOServerLookupListener>> lookupListener;
    private transient List<ContextListener> contextListeners;
    private UpdateStrategy updateStrategy;
    private MOLockStrategy lockStrategy = new DefaultMOLockStrategy();


    public DefaultMOServer() {
        this.registry = new TreeMap<>(new MOScopeComparator());
        this.contexts = new LinkedHashSet<>(10);
        this.lockList = new Hashtable<>(10);
    }


    @Override
    @SuppressWarnings("rawtypes")
    public ManagedObject lookup(MOQuery query) {
        return lookup(query, false, null,
                new MOServerLookupEvent(this, null, query, MOServerLookupEvent.IntendedUse.undefined),
                ManagedObject.class);
    }

    /**
     * Lookup the first (lexicographically ordered) managed object that matches
     * the supplied query and implements the given {@link ManagedObject} class.
     * Locking will be performed according to the set {@link MOLockStrategy} before the lookup
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
     *         the {@link ManagedObject} type filter. Only objects of this type will be looked up and returned.
     *
     * @return the {@code ManagedObject} that matches the query and
     * {@code null} if no such object exists.
     * @since 3.1
     */
    @Override
    public <MO extends ManagedObject<?>>
    MO lookup(MOQuery query, LockRequest lockRequest, MOServerLookupEvent lookupEvent, Class<MO> managedObjectType) {
        return lookup(query, false, lockRequest, lookupEvent, managedObjectType);
    }

    /**
     * Return the locking strategy for this server. The strategy defines if a lock is acquired before
     * a looked up {@link ManagedObject} is returned (and before the corresponding lookup event is being fired) or not.
     *
     * @return the managed object locking strategy instance used by this server. If {@code null}, no locking is performed
     * at all (which is only recommended for static content servers).
     * @since 2.4.0
     */
    public MOLockStrategy getLockStrategy() {
        return lockStrategy;
    }

    /**
     * Sets the lock strategy for this server. The strategy defines if a lock is acquired before
     * a looked up {@link ManagedObject} is returned (and before the corresponding lookup event is being fired) or not.
     * By default, only write access needs a lock.
     *
     * @param lockStrategy
     *         a {@link MOLockStrategy} instance or {@code null} to suppress any locking.
     *
     * @since 2.4.0
     */
    public void setLockStrategy(MOLockStrategy lockStrategy) {
        this.lockStrategy = lockStrategy;
    }

    private <MO extends ManagedObject<?>> MO lookup(MOQuery query,
                                                    boolean specificRegistrationsOnly, LockRequest lockRequest,
                                                    MOServerLookupEvent event, Class<MO> managedObjectType) {

        SortedMap<MOScope, ManagedObject<?>> scope = registry.tailMap(query);
        boolean timedOut = false;
        if (lockRequest != null) {
            lockRequest.setLockRequestStatus(LockRequest.LockStatus.notRequired);
        }
        for (Entry<MOScope, ManagedObject<?>> entry : scope.entrySet()) {
            MOScope key = entry.getKey();
            if (!MOScopeComparator.isQueryContextMatching(query, key)) {
                continue;
            }
            if ((specificRegistrationsOnly) &&
                    (!(key instanceof MOContextScope) || (((MOContextScope) key).getContext() == null))) {
                continue;
            }
            ManagedObject<?> managedObject = entry.getValue();
            MOScope moScope = managedObject.getScope();
            if ((managedObjectType.isInstance(managedObject)) && query.getScope().isOverlapping(moScope)) {
                MO mo = managedObjectType.cast(managedObject);
                event.setLookupResult(mo);
                fireQueryEvent(mo, event);
                // apply locking if needed
                if ((lockStrategy != null) && (lockRequest != null) && (lockRequest.getLockOwner() != null) &&
                        lockStrategy.isLockNeeded(mo, query)) {
                    if (!lock(lockRequest.getLockOwner(), mo, lockRequest.getTimeoutMillis())) {
                        timedOut = true;
                        continue;
                    } else {
                        lockRequest.setLockRequestStatus((timedOut) ?
                                LockRequest.LockStatus.lockedAfterTimeout : LockRequest.LockStatus.locked);
                    }
                }
                if (mo instanceof UpdatableManagedObject) {
                    checkForUpdate((UpdatableManagedObject) mo, query);
                }
                if (query.matchesQuery(mo)) {
                    event.setLookupResult(mo);
                    fireLookupEvent(mo, event);
                    return mo;
                } else if (lockRequest != null) {
                    unlock(lockRequest.getLockOwner(), mo);
                }
            }
        }
        if (timedOut) {
            lockRequest.setLockRequestStatus(LockRequest.LockStatus.lockTimedOut);
        }
        return null;
    }

    /**
     * Checks {@link #updateStrategy} whether the queried managed object needs
     * to be updated. This method is called on behalf of
     * {@link #lookup(MOQuery query)} after {@link #fireQueryEvent} and before
     * {@link #fireLookupEvent} is being called.
     *
     * @param mo
     *         an UpdatableManagedObject instance.
     * @param query
     *         the query that is interested in content of {@code mo}.
     *
     * @since 1.2
     */
    protected void checkForUpdate(UpdatableManagedObject<?> mo, MOQuery query) {
        if (updateStrategy != null) {
            if (updateStrategy.isUpdateNeeded(this, mo, query)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Updating UpdatableManagedObject " + mo +
                            " on behalf of query " + query);
                }
                mo.update(query);
            }
        }
    }

    /**
     * Returns the {@code ManagedObject} with the specified {@code OID}
     * as ID returned by {@link RegisteredManagedObject#getID()} or the lower bound
     * (regardless whether the ManagedObject's scope includes it or not)
     * when registered in the supplied context.
     * <p>
     * Note: The query used to lookup the managed object will indicate an intended
     * read-only access for the {@link MOServerLookupEvent}s fired on behalf of
     * this method.
     *
     * @param key
     *         the OID identifying the key (lower bound) of the
     *         {@code ManagedObject}.
     * @param context
     *         the optional context to look in. A {@code null} value searches
     *         in all contexts.
     * @param fireLookupEvents
     *         if {@code true} lookup and query events will be fired as if the managed
     *         objects has been looked up by {@link #lookup(MOQuery)}. In addition, if
     *         the looked up managed object is an {@link UpdatableManagedObject} it will be locked
     *         if the lock strategy of this server requires it. The lock is active until the look up
     *         events have been fired completely. The lock operation waits without timeout for the lock
     *         to become available.
     *         Otherwise, no events will be fired at all.
     *
     * @return the {@code ManagedObject} instance or {@code null} if such
     * an instance does not exists.
     * @since 2.3
     */
    public ManagedObject<?> getManagedObject(OID key, OctetString context, boolean fireLookupEvents) {
        MOContextScope scope =
                new DefaultMOContextScope(context, key, true, key, true);
        MOQuery query = new DefaultMOQuery(scope);
        SortedMap<MOScope, ManagedObject<?>> reducedScope = registry.tailMap(query);
        for (Entry<MOScope, ManagedObject<?>> entry : reducedScope.entrySet()) {
            MOScope compareScope = entry.getKey();
            if (!MOScopeComparator.isQueryContextMatching(query, compareScope)) {
                continue;
            }
            ManagedObject<?> mo = entry.getValue();
            if (((mo instanceof RegisteredManagedObject) && ((RegisteredManagedObject<?>) mo).getID().equals(key)) ||
                    (!(mo instanceof RegisteredManagedObject) && key.equals(mo.getScope().getLowerBound()))) {
                if (fireLookupEvents) {
                    MOServerLookupEvent event =
                            new MOServerLookupEvent(this, mo, query, MOServerLookupEvent.IntendedUse.undefined);
                    fireQueryEvent(mo, event);
                    boolean locked = false;
                    if (mo instanceof UpdatableManagedObject) {
                        locked = lock(this, mo);
                        if (locked) {
                            checkForUpdate((UpdatableManagedObject<?>) mo, query);
                        }
                    }
                    fireLookupEvent(mo, event);
                    if (locked) {
                        unlock(this, mo);
                    }
                }
                return mo;
            }
        }
        return null;
    }

    /**
     * Returns the {@code ManagedObject} with the specified {@code OID}
     * as ID returned by {@link RegisteredManagedObject#getID()} or the lower bound
     * (regardless whether the ManagedObject's scope includes it or not)
     * when registered in the supplied context.
     * <p>
     * Note: The query used to lookup the managed object will indicate an intended
     * read-only access for the {@link MOServerLookupEvent}s fired on behalf of
     * this method.
     *
     * @param key
     *         the OID identifying the key (lower bound) of the
     *         {@code ManagedObject}.
     * @param context
     *         the optional context to look in. A {@code null} value searches
     *         in all contexts.
     *
     * @return the {@code ManagedObject} instance or {@code null} if such
     * an instance does not exists.
     * @since 1.1
     */
    public ManagedObject<?> getManagedObject(OID key, OctetString context) {
        return getManagedObject(key, context, true);
    }

    /**
     * Returns the value of a particular MIB object instance using the
     * {@link ManagedObjectValueAccess} interface. If a {@link ManagedObject}
     * does not support this interface, its value cannot be returned and
     * {@code null} will be returned instead.
     * Note: This method does not perform any locking based on the {@link MOLockStrategy}.
     *
     * @param server
     *         the {@code MOServer} where to lookup the value.
     * @param context
     *         the optional context to look in. A {@code null} value searches
     *         in all contexts.
     * @param key
     *         the OID identifying the variable instance to return.
     *
     * @return the {@code Variable} associated with {@code OID} and
     * {@code context} in {@code server} or {@code null} if
     * no such variable exists.
     * @since 1.4
     */
    public static Variable getValue(MOServer server, OctetString context, OID key) {
        MOContextScope scope =
                new DefaultMOContextScope(context, key, true, key, true);
        MOServerLookupEvent lookupEvent =
                new MOServerLookupEvent(server, null, new DefaultMOQuery(scope),
                        MOServerLookupEvent.IntendedUse.get, true);
        ManagedObject<?> mo = server.lookup(lookupEvent.getQuery(), null, lookupEvent);
        if (mo instanceof ManagedObjectValueAccess) {
            Variable variable = ((ManagedObjectValueAccess) mo).getValue(key);
            lookupEvent.completedUse(variable);
            return variable;
        }
        return null;
    }

    /**
     * Sets the value of a particular MIB object instance using the
     * {@link ManagedObjectValueAccess} interface. If a {@link ManagedObject}
     * does not support this interface, its value cannot be set and
     * {@code false} will be returned.
     * Note: This method does not perform any locking based on the {@link MOLockStrategy}.
     *
     * @param server
     *         the {@code MOServer} where to lookup the value.
     * @param context
     *         the optional context to look in. A {@code null} value searches
     *         in all contexts.
     * @param newValueAndKey
     *         the OID identifying the variable instance to set and its new value.
     *
     * @return the {@code true} if the value has been set successfully,
     * {@code false} otherwise.
     * @since 1.4
     */
    public static boolean setValue(MOServer server, OctetString context,
                                   VariableBinding newValueAndKey) {
        OID key = newValueAndKey.getOid();
        MOContextScope scope =
                new DefaultMOContextScope(context, key, true, key, true);
        MOServerLookupEvent lookupEvent = new MOServerLookupEvent(server, null,
                new DefaultMOQuery(scope), MOServerLookupEvent.IntendedUse.update, true);
        ManagedObject<?> mo = server.lookup(lookupEvent.getQuery(), null, lookupEvent);
        if (mo instanceof ManagedObjectValueAccess) {
            boolean variableSet = ((ManagedObjectValueAccess) mo).setValue(newValueAndKey);
            if (variableSet) {
                lookupEvent.completedUse(newValueAndKey);
            } else {
                lookupEvent.completedUse(null);
            }
            return variableSet;
        }
        lookupEvent.completedUse(null);
        return false;
    }

    protected void fireLookupEvent(ManagedObject<?> mo, MOServerLookupEvent event) {
        if (lookupListener != null) {
            List<MOServerLookupListener> l = lookupListener.get(mo);
            if (l != null) {
                callLookupListeners(event, l);
            }
            l = lookupListener.get(null);
            if (l != null) {
                callLookupListeners(event, l);
            }
        }
    }

    private void callLookupListeners(MOServerLookupEvent event, List<MOServerLookupListener> l) {
        // avoid concurrent modification exception
        ArrayList<MOServerLookupListener> listCopy = new ArrayList<>(l);
        for (MOServerLookupListener item : listCopy) {
            item.lookupEvent(event);
        }
    }

    protected void fireQueryEvent(ManagedObject<?> mo, MOServerLookupEvent event) {
        if (lookupListener != null) {
            List<MOServerLookupListener> l = lookupListener.get(mo);
            if (l != null) {
                // avoid concurrent modification exception
                l = new ArrayList<>(l);
                for (MOServerLookupListener item : l) {
                    item.queryEvent(event);
                }
            }
        }
    }

    public OctetString[] getContexts() {
        return contexts.toArray(new OctetString[0]);
    }

    public boolean isContextSupported(OctetString context) {
        if ((context == null) || (context.length() == 0)) {
            return true;
        }
        return contexts.contains(context);
    }

    public SortedMap<MOScope, ManagedObject<?>> getRegistry() {
        return registry;
    }

    /**
     * Gets the update strategy for {@link UpdatableManagedObject}s. If the
     * strategy is {@code null} no updates will be performed on behalf
     * of calls to {@link #lookup}.
     *
     * @return the current UpdateStrategy instance or {@code null} if no
     * strategy is active.
     * @see #lookup
     * @since 1.2
     */
    public UpdateStrategy getUpdateStrategy() {
        return updateStrategy;
    }

    /**
     * Sets the update strategy for {@link UpdatableManagedObject}s. If the
     * strategy is {@code null} no updates will be performed on behalf
     * of calls to {@link #lookup(MOQuery)}.
     *
     * @param updateStrategy
     *         the new UpdateStrategy instance or {@code null} if no
     *         updates should be performed.
     *
     * @see #lookup(MOQuery)
     * @since 1.2
     */
    public void setUpdateStrategy(UpdateStrategy updateStrategy) {
        this.updateStrategy = updateStrategy;
    }

    @Override
    public void register(ManagedObject<?> mo, OctetString context) throws DuplicateRegistrationException {
        if ((context == null) || (context.length() == 0)) {
            MOContextScope contextScope =
                    new DefaultMOContextScope(null, mo.getScope());
            MOServerLookupEvent lookupEvent =
                    new MOServerLookupEvent(this, mo, new DefaultMOQuery(contextScope),
                            MOServerLookupEvent.IntendedUse.register);
            ManagedObject<?> other = lookup(new DefaultMOQuery(contextScope), null, lookupEvent);
            if (other != null) {
                throw new DuplicateRegistrationException(contextScope, other.getScope());
            }
            registry.put(mo.getScope(), mo);
            if (logger.isInfoEnabled()) {
                logger.info("Registered MO [" + mo.getClass().getSimpleName() + "] in default context with scope " +
                        mo.getScope());
            }
        } else {
            DefaultMOContextScope contextScope =
                    new DefaultMOContextScope(context, mo.getScope());
            MOServerLookupEvent lookupEvent =
                    new MOServerLookupEvent(this, mo, new DefaultMOQuery(contextScope),
                            MOServerLookupEvent.IntendedUse.register);
            ManagedObject<?> other =
                    lookup(lookupEvent.getQuery(), true, null, lookupEvent, ManagedObject.class);
            if (other != null) {
                throw new DuplicateRegistrationException(contextScope, other.getScope());
            }
            registry.put(contextScope, mo);
            if (logger.isInfoEnabled()) {
                logger.info("Registered MO [" + mo.getClass().getSimpleName() + "] in context " + context + " with scope " +
                        contextScope);
            }
        }
    }

    @Override
    public ManagedObject<?> unregister(ManagedObject<?> mo, OctetString context) {
        MOScope key;
        if ((context == null) || (context.length() == 0)) {
            key = mo.getScope();
        } else {
            key = new DefaultMOContextScope(context, mo.getScope());
        }
        ManagedObject<?> r = registry.remove(key);
        if (r == null) {
            // OK, may be the upper bound of the scope has been adjusted so we need to
            // check that by iterating
            SortedMap<MOScope, ManagedObject<?>> tailMap = registry.tailMap(key);
            for (Iterator<Entry<MOScope, ManagedObject<?>>> it = tailMap.entrySet().iterator(); it.hasNext(); ) {
                Entry<MOScope, ManagedObject<?>> entry = it.next();
                MOScope entryKey = entry.getKey();
                if ((entry.getValue().equals(mo)) &&
                        (context == null || ((entryKey instanceof MOContextScope) &&
                                (context.equals(((MOContextScope) entryKey).getContext()))))) {
                    r = entry.getValue();
                    it.remove();
                    break;
                }
            }
        }
        if (r != null) {
            MOServerLookupEvent event =
                    new MOServerLookupEvent(this, r, new DefaultMOQuery(key instanceof MOContextScope ?
                            (MOContextScope) key : new DefaultMOContextScope(null, key)),
                            MOServerLookupEvent.IntendedUse.unregister);
            fireLookupEvent(r, event);
        }
        if (logger.isInfoEnabled()) {
            if (r != null) {
                logger.info("Removed registration " + r + " for " + mo.getScope() +
                        " in context '" + context + "' successfully");
            } else {
                logger.warn("Removing registration failed for " + mo.getScope() +
                        " in context '" + context + "'");
            }
        }
        return r;
    }

    public void addContext(OctetString context) {
        contexts.add(context);
        fireContextChanged(new ContextEvent(this, ContextEvent.CONTEXT_ADDED, context));
    }

    public void removeContext(OctetString context) {
        contexts.remove(context);
        fireContextChanged(new ContextEvent(this, ContextEvent.CONTEXT_REMOVED, context));
    }

    public synchronized boolean lock(Object owner, ManagedObject<?> managedObject) {
        return lock(owner, managedObject, 0);
    }

    public synchronized boolean lock(Object owner, ManagedObject<?> managedObject,
                                     long timeoutMillis) {
        Lock lock;
        long start = System.nanoTime();
        do {
            lock = lockList.get(managedObject);
            if ((lock == null) || ((lock.getOwner() != owner) && (lock.getCount() <= 0))) {
                lockList.put(managedObject, new Lock(owner));
                if (logger.isDebugEnabled()) {
                    logger.debug("Acquired lock on " + managedObject + " for " + owner);
                }
                return true;
            } else if (lock.getOwner() != owner) {
                try {
                    while ((lock.getCount() > 0) &&
                            ((System.nanoTime() - start) / SnmpConstants.MILLISECOND_TO_NANOSECOND < timeoutMillis)) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Waiting for lock on " + managedObject);
                        }
                        if (timeoutMillis <= 0) {
                            wait();
                        } else {
                            wait(Math.max(timeoutMillis -
                                    (System.nanoTime() - start) / SnmpConstants.MILLISECOND_TO_NANOSECOND, 1));
                        }
                    }
                } catch (InterruptedException ex) {
                    logger.warn("Waiting for lock on " + managedObject +
                            " has been interrupted!");
                    break;
                }
            } else {
                lock.add();
                if (logger.isDebugEnabled()) {
                    logger.debug("Added lock on " + managedObject + " for " + owner);
                }
                return true;
            }
        }
        while (((timeoutMillis <= 0) ||
                ((System.nanoTime() - start) / SnmpConstants.MILLISECOND_TO_NANOSECOND < timeoutMillis)));
        return false;
    }

    public synchronized boolean unlock(Object owner, ManagedObject<?> managedObject) {
        if (managedObject != null) {
            Lock lock = lockList.get(managedObject);
            if (lock != null) {
                if (lock.getOwner() != owner) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Object '" + owner + "' is not owner of lock: " + lock);
                    }
                } else if (lock.remove()) {
                    lockList.remove(managedObject);
                    if (logger.isDebugEnabled()) {
                        logger.debug("Removed lock on " + managedObject + " by " + owner);
                    }
                    notify();
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public Iterator<Entry<MOScope, ManagedObject<?>>> iterator() {
        return iterator(new MOScopeComparator(), null);
    }

    @Override
    public Iterator<Entry<MOScope, ManagedObject<?>>> iterator(Comparator<MOScope> comparator, MOFilter moFilter) {
        synchronized (registry) {
            SortedMap<MOScope, ManagedObject<?>> r = new TreeMap<>(comparator);
            if (moFilter != null) {
                for (Map.Entry<MOScope, ManagedObject<?>> entry : registry.entrySet()) {
                    if (moFilter.passesFilter(entry.getValue())) {
                        r.put(entry.getKey(), entry.getValue());
                    }
                }
            }
            else {
                r.putAll(registry);
            }
            return r.entrySet().iterator();
        }
    }

    public synchronized void addLookupListener(MOServerLookupListener listener,
                                               ManagedObject<?> mo) {
        if (lookupListener == null) {
            lookupListener = Collections.synchronizedMap(new HashMap<>());
        }
        List<MOServerLookupListener> l =
                lookupListener.computeIfAbsent(mo, k -> Collections.synchronizedList(new LinkedList<>()));
        l.add(listener);
    }

    public synchronized boolean removeLookupListener(MOServerLookupListener listener, ManagedObject<?> mo) {
        if (lookupListener != null) {
            List<MOServerLookupListener> l = lookupListener.get(mo);
            if (l != null) {
                return l.remove(listener);
            }
        }
        return false;
    }

    public synchronized void addContextListener(ContextListener l) {
        if (contextListeners == null) {
            contextListeners = new ArrayList<>(2);
        }
        contextListeners.add(l);
    }

    public synchronized void removeContextListener(ContextListener l) {
        if (contextListeners != null) {
            contextListeners.remove(l);
        }
    }

    protected void fireContextChanged(ContextEvent event) {
        if (contextListeners != null) {
            List<ContextListener> listeners = contextListeners;
            for (ContextListener listener : listeners) {
                listener.contextChanged(event);
            }
        }
    }

    public String toString() {
        StringBuilder buf = new StringBuilder(getClass().getName());
        buf.append("[contexts=");
        buf.append(contexts);
        buf.append("[keys={");
        for (Iterator<MOScope> it = registry.keySet().iterator(); it.hasNext(); ) {
            MOScope scope = it.next();
            buf.append(scope.getLowerBound());
            if (scope.isLowerIncluded()) {
                buf.append("+");
            }
            buf.append("-");
            buf.append(scope.getUpperBound());
            if (scope.isUpperIncluded()) {
                buf.append("+");
            }
            if (scope instanceof MOContextScope) {
                buf.append("(").append(((MOContextScope) scope).getContext()).append(")");
            }
            if (it.hasNext()) {
                buf.append(",");
            }
        }
        buf.append("}");
        buf.append(",registry=").append(registry);
        buf.append(",lockList=").append(lockList);
        buf.append(",lookupListener=").append(lookupListener);
        buf.append("]");
        return buf.toString();
    }

    @Override
    public OctetString[] getRegisteredContexts(ManagedObject<?> managedObject) {
        Set<OctetString> contextSet = new HashSet<>();
        SortedMap<MOScope, ManagedObject<?>> scope = registry.tailMap(new DefaultMOContextScope(null,
                managedObject.getScope()));
        for (Entry<MOScope, ManagedObject<?>> entry : scope.entrySet()) {
            MOScope key = entry.getKey();
            ManagedObject<?> o = entry.getValue();
            if (managedObject.equals(o)) {
                if (key instanceof MOContextScope) {
                    contextSet.add(((MOContextScope) key).getContext());
                } else {
                    contextSet.add(null);
                }
            }
        }
        return contextSet.toArray(new OctetString[0]);
    }

    @Override
    public Map<OctetString, MOScope> getRegisteredScopes(ManagedObject<?> managedObject) {
        Map<OctetString, MOScope> scopes = new HashMap<>();
        SortedMap<MOScope, ManagedObject<?>> scope = registry.tailMap(new DefaultMOContextScope(null,
                managedObject.getScope()));
        for (Entry<MOScope, ManagedObject<?>> entry : scope.entrySet()) {
            MOScope key = entry.getKey();
            ManagedObject<?> o = entry.getValue();
            if (managedObject.equals(o)) {
                if (key instanceof MOContextScope) {
                    scopes.put(((MOContextScope)key).getContext(), key);
                }
                else {
                    scopes.put(null, key);
                }
            }
        }
        return scopes;
    }

    /**
     * Register a single {@link MOTableRowListener} with all tables in the
     * specified {@link MOServer}. This overall registration can be used,
     * for example, to apply table size limits to all tables in an agent.
     * See {@link org.snmp4j.agent.mo.util.MOTableSizeLimit} for details.
     * <p>
     * Note: The server must not change its registration content while this
     * method is being called, otherwise a
     * {@link java.util.ConcurrentModificationException} might be thrown.
     *
     * @param server
     *         a {@code MOServer} instance.
     * @param listener
     *         the {@code MOTableRowListener} instance to register.
     * @param <R>
     *         the {@link MOTableRow} type supported by the table row listener to register.
     * @param <T>
     *         the {@link MOTable} type supported by the table row listener to register.
     *
     * @since 1.4
     */
    @SuppressWarnings({"unchecked","rawtypes"})
    public static <R extends MOTableRow, T extends MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>>>
    void registerTableRowListener(MOServer server, MOTableRowListener<R> listener) {
        for (Iterator<Map.Entry<MOScope, ManagedObject<?>>> it = server.iterator(); it.hasNext(); ) {
            ManagedObject<?> mo = it.next().getValue();
            if (mo instanceof MOTable) {
                ((T) mo).addMOTableRowListener(listener);
            }
        }
    }

    /**
     * Unregister a single {@link MOTableRowListener} with all tables in the
     * specified {@link MOServer}. This overall unregistration can be used,
     * for example, to remove table size limits from all tables in an agent.
     * See {@link org.snmp4j.agent.mo.util.MOTableSizeLimit} for details.
     * <p>
     * Note: The server must not change its registration content while this
     * method is being called, otherwise a
     * {@link java.util.ConcurrentModificationException} might be thrown.
     *
     * @param server
     *         a {@code MOServer} instance.
     * @param listener
     *         the {@code MOTableRowListener} instance to unregister.
     * @param <R>
     *         the {@link MOTableRow} type supported by the table row listener to register.
     * @param <T>
     *         the {@link MOTable} type supported by the table row listener to register.
     *
     * @since 1.4
     */
    @SuppressWarnings({"unchecked","rawtypes"})
    public static <R extends MOTableRow, T extends MOTable<R, ? extends MOColumn, ? extends MOTableModel<R>>>
    void unregisterTableRowListener(MOServer server, MOTableRowListener<R> listener) {
        for (Iterator<Map.Entry<MOScope, ManagedObject<?>>> it = server.iterator(); it.hasNext(); ) {
            ManagedObject<?> mo = it.next().getValue();
            if (mo instanceof MOTable) {
                ((T) mo).removeMOTableRowListener(listener);
            }
        }
    }

    /**
     * Register a single {@link MOChangeListener} with all objects matching the given filter in the
     * specified {@link MOServer}. This overall registration can be used,
     * for example, to listen for object changes.
     * <p>
     * Note: The server must not change its registration content while this
     * method is being called, otherwise a
     * {@link java.util.ConcurrentModificationException} might be thrown.
     *
     * @param server
     *         a {@code MOServer} instance.
     * @param listener
     *         the {@code MOTableRowListener} instance to register.
     * @param moFilter
     *         an optional filter to select objects which should register the provided listener.
     *
     * @since 3.0
     */
    public static void registerChangeListener(MOServer server, MOChangeListener listener, MOFilter moFilter) {
        for (Iterator<Map.Entry<MOScope, ManagedObject<?>>> it = server.iterator(); it.hasNext(); ) {
            ManagedObject<?> mo = it.next().getValue();
            if (mo instanceof ChangeableManagedObject && (moFilter == null || moFilter.passesFilter(mo))) {
                ((ChangeableManagedObject) mo).addMOChangeListener(listener);
            }
        }
    }

    /**
     * Unregister a single {@link MOChangeListener} from all objects matching the given filter in the
     * specified {@link MOServer}.
     * <p>
     * Note: The server must not change its registration content while this
     * method is being called, otherwise a
     * {@link java.util.ConcurrentModificationException} might be thrown.
     *
     * @param server
     *         a {@code MOServer} instance.
     * @param listener
     *         the {@code MOTableRowListener} instance to unregister.
     * @param moFilter
     *         an optional filter to select objects which should no longer register the provided listener.
     *
     * @since 3.0
     */
    public static void unregisterChangeListener(MOServer server, MOChangeListener listener, MOFilter moFilter) {
        for (Iterator<Map.Entry<MOScope, ManagedObject<?>>> it = server.iterator(); it.hasNext(); ) {
            ManagedObject<?> mo = it.next().getValue();
            if (mo instanceof ChangeableManagedObject && (moFilter == null || moFilter.passesFilter(mo))) {
                ((ChangeableManagedObject) mo).removeMOChangeListener(listener);
            }
        }
    }


    static class Lock {
        private Object owner;
        private long creationTime;
        private int count = 0;

        private Lock() {
            this.creationTime = System.currentTimeMillis();
            this.count = 0;
        }

        Lock(Object owner) {
            this();
            this.owner = owner;
            this.count = 1;
        }

        public long getCreationTime() {
            return creationTime;
        }

        public int getCount() {
            return count;
        }

        public synchronized void add() {
            count++;
        }

        public synchronized boolean remove() {
            if ((--count) <= 0) {
                if (count != 0) {
                    count = 0;
                }
                return true;
            }
            return false;
        }

        public Object getOwner() {
            return owner;
        }

        @Override
        public String toString() {
            return "Lock[" +
                    "owner=" + owner +
                    ", creationTime=" + creationTime +
                    ", count=" + count +
                    ']';
        }
    }

}
