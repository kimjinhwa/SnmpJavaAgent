/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - DefaultMOFactory.java  
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

package org.snmp4j.agent.mo;

import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.snmp.SNMPv2MIB;
import org.snmp4j.agent.mo.snmp.SysUpTime;
import org.snmp4j.smi.*;

import java.util.Map;

import org.snmp4j.agent.mo.snmp.tc.TextualConvention;

import java.util.HashMap;

import org.snmp4j.agent.mo.snmp.SNMPv2TC;

import java.util.*;

/**
 * The <code>DefaultMOFactory</code> is the default factory for creating ManagedObjects. The default factory creates
 * columnar and scalar objects based on SNMPv2-TC textual conventions with appropriate constraints. Other textual
 * conventions can be added too.
 *
 * @author Frank Fock
 * @version 2.3.0
 */
public class DefaultMOFactory implements MOFactory, LinkedMOFactory, MOTableRowFactory<DefaultMOMutableRow2PC> {

    private Map<String, Map<String, TextualConvention<?>>> textualConventions = new HashMap<>();
    private Map<OID, Object> links;

    private static MOFactory instance;

    protected DefaultMOFactory() {
    }

    /**
     * Returns the factory singleton with default support for SNMPv2-TC textual conventions.
     *
     * @return a MOFactory instance.
     */
    public static MOFactory getInstance() {
        if (instance == null) {
            instance = new DefaultMOFactory();
            addSNMPv2TCs(instance);
        }
        return instance;
    }

    /**
     * Sets the singleton factory.
     *
     * @param factory
     *         a MOFactory instance.
     */
    public static void setInstance(MOFactory factory) {
        instance = factory;
    }

    /**
     * Adds support for SNMPv2TC textual conventions to the supplied ManagedObject factory.
     *
     * @param factory
     *         a MOFactory instance.
     */
    public static void addSNMPv2TCs(MOFactory factory) {
        Collection<TextualConvention<?>> tcs = new SNMPv2TC().getTextualConventions();
        for (TextualConvention<?> tc : tcs) {
            factory.addTextualConvention(tc);
        }
    }

    protected Map<? extends String, ? extends Map<String, TextualConvention<?>>> getTextualConventions() {
        return textualConventions;
    }

    /**
     * Adds a textual convention to this factory which can then be used by the factory to create appropriate value
     * constraints for columnar and scalar managed objects.
     *
     * @param tc
     *         a TextualConvention instance.
     */
    @Override
    public synchronized void addTextualConvention(TextualConvention<?> tc) {
        Map<String, TextualConvention<?>> tcMap =
                textualConventions.computeIfAbsent(tc.getModuleName(), k -> new HashMap<>(10));
        tcMap.put(tc.getName(), tc);
    }

    @Override
    public synchronized void removeTextualConvention(TextualConvention<?> tc) {
        Map<String, TextualConvention<?>> tcMap = textualConventions.get(tc.getModuleName());
        if (tcMap != null) {
            tcMap.remove(tc.getName());
            if (tcMap.isEmpty()) {
                textualConventions.remove(tc.getModuleName());
            }
        }
    }

    @SuppressWarnings("unchecked")
    public synchronized <V extends Variable> TextualConvention<V>
    getTextualConvention(String moduleName, String name) {
        Map<String, TextualConvention<?>> tcMap = textualConventions.get(moduleName);
        if (tcMap != null) {
            return (TextualConvention<V>) tcMap.get(name);
        }
        return null;
    }

    @Override
    public DefaultMOMutableRow2PC createRow(OID index, Variable[] values) throws
            UnsupportedOperationException {
        return new DefaultMOMutableRow2PC(index, values);
    }

    @Override
    public void freeRow(DefaultMOMutableRow2PC row) {
    }

    @Override
    public void setLink(OID oid, Object instrumentationHelperObject) {
        if (links == null) {
            initLinkMap();
        }
        links.put(oid, instrumentationHelperObject);
    }

    @Override
    public Object getLink(OID oid) {
        if (links != null) {
            OID searchOID = new OID(oid);
            Object result = null;
            while ((searchOID.size() > 0) &&
                    ((result = links.get(searchOID)) == null)) {
                searchOID.trim(1);
            }
            return result;
        }
        return null;
    }

    protected synchronized void initLinkMap() {
        if (links == null) {
            links = new HashMap<OID, Object>();
        }
    }
}
