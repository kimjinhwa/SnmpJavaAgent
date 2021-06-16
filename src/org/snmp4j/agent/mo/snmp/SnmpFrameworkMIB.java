/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - SnmpFrameworkMIB.java  
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

import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.MOServer;
import org.snmp4j.agent.mo.snmp.tc.SnmpAdminStringTC;
import org.snmp4j.agent.mo.snmp.tc.SnmpEngineIDTC;
import org.snmp4j.agent.mo.snmp.tc.TCModule;
import org.snmp4j.agent.mo.snmp.tc.TextualConvention;
import org.snmp4j.smi.*;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.TransportMapping;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.snmp4j.security.USM;

/**
 * The SnmpFrameworkMIB implements the SNMP-FRAMEWORK-MIB as defined by RFC 3411.
 *
 * @author Frank Fock
 * @version 3.3.6
 */
public class SnmpFrameworkMIB implements MOGroup, TCModule {

    public static final String MODULE_NAME = "SNMP-FRAMEWORK-MIB";

    private USM usm;
    private OctetString engineId;
    private Collection<TransportMapping<? extends Address>> transportMappings;

    private MOScalar<OctetString> snmpEngineID;
    private MOScalar<Integer32> snmpEngineBoots;
    private MOScalar<Integer32> snmpEngineTime;
    private MOScalar<Integer32> snmpEngineMaxMessageSize;

    public static final String SNMPADMINSTRING = "SnmpAdminString";
    public static final String SNMPENGINEID = "SnmpEngineID";

    private Map<String, TextualConvention<?>> textualConventions;

    public SnmpFrameworkMIB(OctetString engineId, USM usm,
                            Collection<TransportMapping<? extends Address>> transportMappings) {
        this.engineId = engineId;
        this.usm = usm;
        this.transportMappings = transportMappings;
        createMOs();
        textualConventions = new HashMap<>(2);
        textualConventions.put(SNMPADMINSTRING, new SnmpAdminStringTC());
        textualConventions.put(SNMPENGINEID, new SnmpEngineIDTC(snmpEngineID.getValue()));
    }

    @Deprecated
    public SnmpFrameworkMIB(OctetString engineId, USM usm,
                            Collection<TransportMapping<? extends Address>> transportMappings,
                            boolean updateUsmFromMIB) {
        this(engineId, usm, transportMappings);
    }

    private void createMOs() {
        snmpEngineID = new MOScalar<OctetString>(new OID("1.3.6.1.6.3.10.2.1.1.0"),
                MOAccessImpl.ACCESS_READ_ONLY,
                null) {
            @Override
            public OctetString getValue() {
                return engineId;
            }
        };
        snmpEngineBoots = new MOScalar<Integer32>(new OID("1.3.6.1.6.3.10.2.1.2.0"),
                MOAccessImpl.ACCESS_READ_ONLY,
                null) {
            @Override
            public Integer32 getValue() {
                return new Integer32(usm.getEngineBoots());
            }
        };
        snmpEngineTime = new MOScalar<Integer32>(new OID("1.3.6.1.6.3.10.2.1.3.0"),
                MOAccessImpl.ACCESS_READ_ONLY,
                null) {
            @Override
            public Integer32 getValue() {
                return new Integer32(usm.getEngineTime());
            }
        };
        Integer32 maxMsgSize = new Integer32(getMaxMessageSize());
        snmpEngineMaxMessageSize = new MOScalar<Integer32>(new OID("1.3.6.1.6.3.10.2.1.4.0"),
                MOAccessImpl.ACCESS_READ_ONLY,
                maxMsgSize);
    }

    private int getMaxMessageSize() {
        int totalMaxMessageSize = 2147483647;
        for (TransportMapping<?> transportMapping : transportMappings) {
            int maxMsgSize = (transportMapping).getMaxInboundMessageSize();
            totalMaxMessageSize = Math.min(totalMaxMessageSize, maxMsgSize);
        }
        return totalMaxMessageSize;
    }

    public void registerMOs(MOServer server, OctetString context) throws
            DuplicateRegistrationException {
        server.register(snmpEngineID, context);
        if (usm != null) {
            server.register(snmpEngineBoots, context);
            server.register(snmpEngineTime, context);
        }
        server.register(snmpEngineMaxMessageSize, context);
    }

    public void unregisterMOs(MOServer server, OctetString context) {
        server.unregister(snmpEngineID, context);
        server.unregister(snmpEngineBoots, context);
        server.unregister(snmpEngineTime, context);
        server.unregister(snmpEngineMaxMessageSize, context);
    }

    public MOScalar<Integer32> getSnmpEngineBoots() {
        return snmpEngineBoots;
    }

    public MOScalar<OctetString> getSnmpEngineID() {
        return snmpEngineID;
    }

    public MOScalar<Integer32> getSnmpEngineMaxMessageSize() {
        return snmpEngineMaxMessageSize;
    }

    public MOScalar<Integer32> getSnmpEngineTime() {
        return snmpEngineTime;
    }

    public USM getUSM() {
        return usm;
    }

    /**
     * Indicates whether changes on the {@link #getSnmpEngineID()}, {@link #getSnmpEngineBoots()}, and {@link
     * #getSnmpEngineTime()} values are propagated to the referenced USM instance. If true, changes of those objects
     * will be applied to the USM.
     *
     * @return {@code true} if changes are propagated.
     *
     */
    @Deprecated
    public boolean isUpdateUsmFromMIB() {
        return false;
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @Override
    public TextualConvention<?> getTextualConvention(String name) {
        return textualConventions.get(name);
    }

    @Override
    public Collection<? extends TextualConvention<?>> getTextualConventions() {
        return textualConventions.values();
    }
}
