/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - SnmpMpdMib.java  
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
//--AgentGen BEGIN=_BEGIN
//--AgentGen END

import org.snmp4j.event.CounterEvent;
import org.snmp4j.event.CounterListener;
import org.snmp4j.smi.*;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.agent.*;
import org.snmp4j.agent.mo.*;
import org.snmp4j.agent.mo.snmp.*;
import org.snmp4j.agent.mo.snmp.smi.*;
import org.snmp4j.agent.request.*;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.agent.mo.snmp.tc.*;


//--AgentGen BEGIN=_IMPORT
//--AgentGen END

public class SnmpMpdMib
//--AgentGen BEGIN=_EXTENDS
//--AgentGen END
        implements MOGroup
//--AgentGen BEGIN=_IMPLEMENTS
        , CounterListener
//--AgentGen END
{

    private static final LogAdapter LOGGER =
            LogFactory.getLogger(SnmpMpdMib.class);

//--AgentGen BEGIN=_STATIC
//--AgentGen END

    // Factory
    private MOFactory moFactory =
            DefaultMOFactory.getInstance();

    // Constants

    /**
     * OID of this MIB module for usage which can be
     * used for its identification.
     */
    public static final OID oidSnmpMpdMib =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 11});

    // Identities
    // Scalars
    public static final OID oidSnmpUnknownSecurityModels =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0});
    public static final OID oidSnmpInvalidMsgs =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 11, 2, 1, 2, 0});
    public static final OID oidSnmpUnknownPDUHandlers =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 11, 2, 1, 3, 0});
    // Tables

    // Notifications

    // Enumerations


    // TextualConventions

    // Scalars
    private MOScalar<Counter32> snmpUnknownSecurityModels;
    private MOScalar<Counter32> snmpInvalidMsgs;
    private MOScalar<Counter32> snmpUnknownPDUHandlers;

    // Tables


//--AgentGen BEGIN=_MEMBERS
//--AgentGen END

    /**
     * Constructs a SnmpMpdMib instance without actually creating its
     * <code>ManagedObject</code> instances. This has to be done in a
     * sub-class constructor or after construction by calling
     * {@link #createMO(MOFactory moFactory)}.
     */
    protected SnmpMpdMib() {
//--AgentGen BEGIN=_DEFAULTCONSTRUCTOR
//--AgentGen END
    }

    /**
     * Constructs a SnmpMpdMib instance and actually creates its
     * <code>ManagedObject</code> instances using the supplied
     * <code>MOFactory</code> (by calling
     * {@link #createMO(MOFactory moFactory)}).
     *
     * @param moFactory the <code>MOFactory</code> to be used to create the
     *                  managed objects for this module.
     */
    public SnmpMpdMib(MOFactory moFactory) {
        this();
        createMO(moFactory);
//--AgentGen BEGIN=_FACTORYCONSTRUCTOR
//--AgentGen END
    }

//--AgentGen BEGIN=_CONSTRUCTORS
//--AgentGen END

    /**
     * Create the ManagedObjects defined for this MIB module
     * using the specified {@link MOFactory}.
     *
     * @param moFactory the <code>MOFactory</code> instance to use for object
     *                  creation.
     */
    protected void createMO(MOFactory moFactory) {
        addTCsToFactory(moFactory);
        snmpUnknownSecurityModels =
                moFactory.createScalar(oidSnmpUnknownSecurityModels,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY),
                        new Counter32());
        snmpInvalidMsgs =
                moFactory.createScalar(oidSnmpInvalidMsgs,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY),
                        new Counter32());
        snmpUnknownPDUHandlers =
                moFactory.createScalar(oidSnmpUnknownPDUHandlers,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY),
                        new Counter32());
    }

    public MOScalar<Counter32> getSnmpUnknownSecurityModels() {
        return snmpUnknownSecurityModels;
    }

    public MOScalar<Counter32> getSnmpInvalidMsgs() {
        return snmpInvalidMsgs;
    }

    public MOScalar<Counter32> getSnmpUnknownPDUHandlers() {
        return snmpUnknownPDUHandlers;
    }


    public void registerMOs(MOServer server, OctetString context)
            throws DuplicateRegistrationException {
        // Scalar Objects
        server.register(this.snmpUnknownSecurityModels, context);
        server.register(this.snmpInvalidMsgs, context);
        server.register(this.snmpUnknownPDUHandlers, context);
//--AgentGen BEGIN=_registerMOs
//--AgentGen END
    }

    public void unregisterMOs(MOServer server, OctetString context) {
        // Scalar Objects
        server.unregister(this.snmpUnknownSecurityModels, context);
        server.unregister(this.snmpInvalidMsgs, context);
        server.unregister(this.snmpUnknownPDUHandlers, context);
//--AgentGen BEGIN=_unregisterMOs
//--AgentGen END
    }

    // Notifications

    // Scalars

    // Value Validators


    // Rows and Factories


    //--AgentGen BEGIN=_METHODS
    public void incrementCounter(CounterEvent event) {
        Counter32 current = null;
        if (oidSnmpUnknownSecurityModels.equals(event.getOid())) {
            current = snmpUnknownSecurityModels.getValue();
        }
        else if (oidSnmpUnknownPDUHandlers.equals(event.getOid())) {
            current = snmpUnknownPDUHandlers.getValue();
        }
        else if (oidSnmpInvalidMsgs.equals(event.getOid())) {
            current = snmpInvalidMsgs.getValue();
        }
        if (current != null) {
            current.increment();
            event.setCurrentValue((Counter32) current.clone());
        }
    }
//--AgentGen END

    // Textual Definitions of MIB module SnmpMpdMib
    protected void addTCsToFactory(MOFactory moFactory) {
    }


//--AgentGen BEGIN=_TC_CLASSES_IMPORTED_MODULES_BEGIN
//--AgentGen END

    // Textual Definitions of other MIB modules
    public void addImportedTCsToFactory(MOFactory moFactory) {
    }


//--AgentGen BEGIN=_TC_CLASSES_IMPORTED_MODULES_END
//--AgentGen END

//--AgentGen BEGIN=_CLASSES
//--AgentGen END

//--AgentGen BEGIN=_END
//--AgentGen END
}


