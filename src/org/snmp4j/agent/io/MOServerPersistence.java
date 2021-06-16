/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOServerPersistence.java  
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

import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.MOPriorityProvider;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.agent.util.MOScopePriorityComparator;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.util.*;

import java.util.Map.Entry;

import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogAdapter;

/**
 * The {@code MOServerPersistence} provides persistence operations
 * to load and save serialized MIB data.
 *
 * @author Frank Fock
 * @version 1.4
 */
public class MOServerPersistence {

    private static final LogAdapter logger =
            LogFactory.getLogger(MOServerPersistence.class);

    private final MOServer[] servers;

    public MOServerPersistence(MOServer server) {
        this(new MOServer[]{server});
    }

    public MOServerPersistence(MOServer[] moServers) {
        this.servers = moServers;
    }

    private HashMap<OctetString, LinkedHashMap<OID, SerializableManagedObject<?>>> buildCache(
            MOPriorityProvider priorityProvider)
    {
        HashMap<OctetString, LinkedHashMap<OID, SerializableManagedObject<?>>> serializableMO = new HashMap<>();
        SortedMap<OID, Integer> priorityMap = null;
        ManagedObject<?> bootMO = null;
        if (priorityProvider != null) {
            priorityMap = priorityProvider.getPriorityMap(null);
            bootMO = priorityProvider.getBootManagedObject(null);
        }
        for (MOServer server : servers) {
            MOScopeComparator scopeComparator = new MOScopeComparator();
            if (priorityMap != null && bootMO != null) {
                priorityMap.put(bootMO.getScope().getLowerBound(), -1);
                scopeComparator = new MOScopePriorityComparator(priorityMap);
                if (logger.isDebugEnabled()) {
                    logger.debug("Using priority map "+priorityMap+" to prepare managed object de/serialization");
                }
            }
            for (Iterator<Entry<MOScope, ManagedObject<?>>> it = server.iterator(scopeComparator, null); it.hasNext();) {
                Entry<MOScope, ManagedObject<?>> entry = it.next();
                MOScope scope = entry.getKey();
                ManagedObject<?> value = entry.getValue();
                if ((value instanceof SerializableManagedObject) &&
                        (!((SerializableManagedObject<?>) value).isVolatile())) {
                    OctetString context = null;
                    if (scope instanceof MOContextScope) {
                        context = ((MOContextScope) scope).getContext();
                    }
                    LinkedHashMap<OID, SerializableManagedObject<?>> objects =
                            serializableMO.computeIfAbsent(context, k -> new LinkedHashMap<>());
                    objects.put(((SerializableManagedObject<?>) value).getID(), (SerializableManagedObject<?>) value);
                }
            }
        }
        return serializableMO;
    }

    public synchronized void loadData(MOInput input) throws IOException {
        HashMap<OctetString, LinkedHashMap<OID, SerializableManagedObject<?>>> serializableMO = buildCache(null);
        // load context independent data
        LinkedHashMap<OID, SerializableManagedObject<?>> mos = serializableMO.get(null);
        if (mos != null) {
            readData(input, mos);
        } else {
            Sequence seq = input.readSequence();
            for (int i = 0; i < seq.getSize(); i++) {
                MOInfo mo = input.readManagedObject();
                input.skipManagedObject(mo);
            }
        }
        // load contexts
        Sequence contextSequence = input.readSequence();
        if (contextSequence != null) {
            for (int i = 0; i < contextSequence.getSize(); i++) {
                Context context = input.readContext();
                boolean skip = true;
//      MOServer server = null;
                for (int s = 0; (skip) && (s < servers.length); s++) {
                    if (servers[s].isContextSupported(context.getContext())) {
                        skip = false;
//          server = servers[s];
                    }
                }
                if (skip) {
                    logger.warn("Context '" + context.getContext() + "' is no longer supported by agent");
                    input.skipContext(context);
                    continue;
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("Loading data for context '" + context.getContext() + "'");
                }
                mos = serializableMO.get(context.getContext());
                if (mos == null) {
                    input.skipContext(context);
                    continue;
                }
                readData(input, mos);
                input.skipContext(context);
            }
        }
    }

    private static void readData(MOInput input, LinkedHashMap<OID, SerializableManagedObject<?>> mos)
            throws IOException {
        Sequence moGroup = input.readSequence();
        if (moGroup != null) {
            for (int j = 0; j < moGroup.getSize(); j++) {
                MOInfo moid = input.readManagedObject();
                if (logger.isDebugEnabled()) {
                    logger.debug("Looking up object " + moid.getOID());
                }
                SerializableManagedObject<?> mo = mos.get(moid.getOID());
                if (mo != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Loading data for object " + moid.getOID());
                    }
                    mo.load(input);
                }
                input.skipManagedObject(moid);
            }
        }
    }

    /**
     * Saves the serializable data of the associated servers to the given
     * {@link MOOutput}. This method can be called while the registrations
     * of the {@link MOServer}s are changed, because {@link MOServer#iterator()}
     * is synchronized and returns a copy tree of the registered objects.
     *
     * @param output
     *         a {@code MOOutput} instance to store the data.
     *
     * @throws IOException
     *         if the output stream cannot be written.
     */
    public synchronized void saveData(MOOutput output) throws IOException {
        saveData(output, null);
    }

    private static void writeData(MOOutput output, Context c,
                                  LinkedHashMap<? extends OID, SerializableManagedObject<?>> mos)
            throws IOException {
        if (logger.isDebugEnabled()) {
            if (c == null) {
                logger.debug("Writing " + mos.size() + " context independent managed objects");
            } else {
                logger.debug("Writing " + mos.size() + " managed objects for context '" + c.getContext() + "'");
            }
        }
        output.writeSequence(new Sequence(mos.size()));
        for (SerializableManagedObject<?> mo : mos.values()) {
            MOInfo moInfo = new MOInfo(mo.getID());
            output.writeManagedObjectBegin(moInfo);
            mo.save(output);
            output.writeManagedObjectEnd(moInfo);
            if (logger.isDebugEnabled()) {
                logger.debug("Wrote data of "+moInfo.getOID());
            }
        }
    }

    /**
     * Saves the serializable data of the associated servers to the given
     * {@link MOOutput} in the order defined by {@link MOPriorityProvider}.
     * This method can be called while the registrations
     * of the {@link MOServer}s are changed, because {@link MOServer#iterator()}
     * is synchronized and returns a copy tree of the registered objects.
     *
     * @param output
     *         a {@code MOOutput} instance to store the data.
     * @param priorityProvider
     *         if not {@code null}, the objects of the servers are stored in order defined by this priority provider.
     *         Objects with lowest priority value, will be saved first.
     * @throws IOException
     *         if the output stream cannot be written.
     */
    public void saveData(MOOutput output, MOPriorityProvider priorityProvider) throws IOException {
        HashMap<OctetString, LinkedHashMap<OID, SerializableManagedObject<?>>> serializableMO =
                buildCache(priorityProvider);
        // write context independent data
        LinkedHashMap<? extends OID, SerializableManagedObject<?>> mos = serializableMO.get(null);
        if (mos != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Trying to write MIB data for all contexts: "+mos.keySet());
            }
            writeData(output, null, mos);
        } else {
            output.writeSequence(new Sequence(0));
        }
        Set<OctetString> contextSet = new HashSet<OctetString>();
        for (MOServer server : servers) {
            contextSet.addAll(Arrays.asList(server.getContexts()));
        }
        OctetString[] contexts = contextSet.toArray(new OctetString[0]);
        output.writeSequence(new Sequence(contexts.length));
        for (OctetString context : contexts) {
            Context c = new Context(context);
            output.writeContextBegin(c);
            if (logger.isDebugEnabled()) {
                logger.debug("Trying to write MIB data for context '" + c.getContext() + "'");
            }
            mos = serializableMO.get(c.getContext());
            if (mos != null) {
                writeData(output, c, mos);
            }
            output.writeContextEnd(c);
        }
    }
}
