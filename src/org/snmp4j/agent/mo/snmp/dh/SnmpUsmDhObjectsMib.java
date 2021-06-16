/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - SnmpUsmDhObjectsMib.java  
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


package org.snmp4j.agent.mo.snmp.dh;

//--AgentGen BEGIN=_BEGIN
//--AgentGen END

import org.snmp4j.PDU;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.security.*;
import org.snmp4j.security.dh.DHOperations;
import org.snmp4j.security.dh.DHParameters;
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

import org.snmp4j.agent.mo.snmp.UsmMIB.UsmTableRow;

//--AgentGen BEGIN=_IMPORT

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Collection;
//--AgentGen END

public class SnmpUsmDhObjectsMib
//--AgentGen BEGIN=_EXTENDS
//--AgentGen END
        implements MOGroup
//--AgentGen BEGIN=_IMPLEMENTS
//--AgentGen END
{

    private static final LogAdapter LOGGER =
            LogFactory.getLogger(SnmpUsmDhObjectsMib.class);

//--AgentGen BEGIN=_STATIC
//--AgentGen END

    // Factory
    private MOFactory moFactory =
            DefaultMOFactory.getInstance();

    // Constants

    /**
     * OID of this MIB module for usage which can be used for its identification.
     */
    public static final OID oidSnmpUsmDhObjectsMib =
            new OID(new int[]{1, 3, 6, 1, 3, 101});

    // Identities
    // Scalars
    public static final OID oidUsmDHParameters =
            new OID(new int[]{1, 3, 6, 1, 3, 101, 1, 1, 1, 0});
    // Tables

    // Notifications

    // Enumerations


    // TextualConventions
    private static final String TC_MODULE_SNMP_USM_DH_OBJECTS_MIB = "SNMP-USM-DH-OBJECTS-MIB";
    private static final String TC_MODULE_SNMP_FRAMEWORK_MIB = "SNMP-FRAMEWORK-MIB";
    private static final String TC_DHKEYCHANGE = "DHKeyChangeImpl";
    private static final String TC_SNMPADMINSTRING = "SnmpAdminString";

    // Scalars
    private UsmDHParametersImpl usmDHParameters;

    // Tables
    public static final OID oidUsmDHUserKeyEntry =
            new OID(new int[]{1, 3, 6, 1, 3, 101, 1, 1, 2, 1});

    // Index OID definitions
    public static final OID oidUsmUserEngineID =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 1});
    public static final OID oidUsmUserName =
            new OID(new int[]{1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 2});

    // Column TC definitions for usmDHUserKeyEntry:
    public static final String tcModuleSnmpUsmDhObjectsMib = "SNMP-USM-DH-OBJECTS-MIB";
    public static final String tcDefDHKeyChange = "DHKeyChangeImpl";

    // Column sub-identifier definitions for usmDHUserKeyEntry:
    public static final int colUsmDHUserAuthKeyChange = 1;
    public static final int colUsmDHUserOwnAuthKeyChange = 2;
    public static final int colUsmDHUserPrivKeyChange = 3;
    public static final int colUsmDHUserOwnPrivKeyChange = 4;

    // Column index definitions for usmDHUserKeyEntry:
    public static final int idxUsmDHUserAuthKeyChange = 0;
    public static final int idxUsmDHUserOwnAuthKeyChange = 1;
    public static final int idxUsmDHUserPrivKeyChange = 2;
    public static final int idxUsmDHUserOwnPrivKeyChange = 3;

    private MOTableSubIndex[] usmDHUserKeyEntryIndexes;
    private MOTableIndex usmDHUserKeyEntryIndex;

    @SuppressWarnings("rawtypes")
    private MOTable<UsmDHUserKeyEntryRow,
            MOColumn,
            MOTableModel<UsmDHUserKeyEntryRow>> usmDHUserKeyEntry;
    private MOTableModel<UsmDHUserKeyEntryRow> usmDHUserKeyEntryModel;
    public static final OID oidUsmDHKickstartEntry =
            new OID(new int[]{1, 3, 6, 1, 3, 101, 1, 2, 1, 1});

    // Index OID definitions
    public static final OID oidUsmDHKickstartIndex =
            new OID(new int[]{1, 3, 6, 1, 3, 101, 1, 2, 1, 1, 1});

    // Column TC definitions for usmDHKickstartEntry:
    public static final String tcModuleSnmpFrameworkMib = "SNMP-FRAMEWORK-MIB";
    public static final String tcDefSnmpAdminString = "SnmpAdminString";

    // Column sub-identifier definitions for usmDHKickstartEntry:
    public static final int colUsmDHKickstartMyPublic = 2;
    public static final int colUsmDHKickstartMgrPublic = 3;
    public static final int colUsmDHKickstartSecurityName = 4;

    // Column index definitions for usmDHKickstartEntry:
    public static final int idxUsmDHKickstartMyPublic = 0;
    public static final int idxUsmDHKickstartMgrPublic = 1;
    public static final int idxUsmDHKickstartSecurityName = 2;

    private MOTableSubIndex[] usmDHKickstartEntryIndexes;
    private MOTableIndex usmDHKickstartEntryIndex;

    @SuppressWarnings("rawtypes")
    private MOTable<UsmDHKickstartEntryRow,
            MOColumn,
            MOTableModel<UsmDHKickstartEntryRow>> usmDHKickstartEntry;
    private MOTableModel<UsmDHKickstartEntryRow> usmDHKickstartEntryModel;

    @SuppressWarnings("rawtypes")
    private DefaultMOTable<UsmMIB.UsmTableRow, MOColumn, DefaultMOMutableTableModel<UsmMIB.UsmTableRow>> usmUserEntry;
    private MOTableRelation<UsmMIB.UsmTableRow, UsmDHUserKeyEntryRow> usmDHUserKeyEntryRelation;

    //--AgentGen BEGIN=_MEMBERS
    protected USM usm;
    protected UsmMIB usmMIB;
    protected VacmMIB vacmMIB;
    protected Collection<DHKickstartParameters> dhKickstartParameters;
    protected DHOperations dhOperations;
//--AgentGen END

    /**
     * Constructs a SnmpUsmDhObjectsMib instance without actually creating its
     * {@code ManagedObject} instances. This has to be done in a
     * sub-class constructor or after construction by calling {@link #createMO(MOFactory moFactory)}.
     */
    protected SnmpUsmDhObjectsMib() {
//--AgentGen BEGIN=_DEFAULTCONSTRUCTOR
        dhOperations = new DHOperations();
//--AgentGen END
    }

    /**
     * Constructs a SnmpUsmDhObjectsMib instance and actually creates its
     * {@code ManagedObject} instances using the supplied
     * {@code MOFactory} (by calling
     * {@link #createMO(MOFactory moFactory)}).
     *
     * @param moFactory
     *         the {@code MOFactory} to be used to create the managed objects for this module.
     */
    protected SnmpUsmDhObjectsMib(MOFactory moFactory) {
        this();
//--AgentGen BEGIN=_FACTORYCONSTRUCTOR::factoryWrapper
        // wrap MOFactory to use SnmpUsmDHObjectsMibFactoryAdapter
        moFactory = new SnmpUsmDHObjectsMibFactoryAdapter(moFactory);
//--AgentGen END
        this.moFactory = moFactory;
        createMO(moFactory);
//--AgentGen BEGIN=_FACTORYCONSTRUCTOR
//--AgentGen END
    }

//--AgentGen BEGIN=_CONSTRUCTORS

    /**
     * Constructs a SnmpUsmDhObjectsMib instance and actually creates its
     * {@code ManagedObject} instances using the supplied
     * {@code MOFactory} (by calling
     * {@link #createMO(MOFactory moFactory)}).
     *
     * @param moFactory
     *         the {@code MOFactory} to be used to create the managed objects for this module.
     * @param usm
     *         the USM where user authentication and privacy are to be configured using Diffie Helman key exchange.
     * @param usmMIB
     *         the USM MIB where user authentication and privacy are to be configured using Diffie Helman key exchange.
     * @param vacmMIB
     *         the VACM MIB that will receive preinstalled entries as defined by usmDHKeyMIBNCompliance when the objects
     *         of this MIB are being registered.
     * @param dhKickstartParameters
     *         the securityName to public key mappings needed to initialize Diffie Hellman key exchange.
     */
    public SnmpUsmDhObjectsMib(MOFactory moFactory, USM usm, UsmMIB usmMIB, VacmMIB vacmMIB,
                               Collection<DHKickstartParameters> dhKickstartParameters) {
        this();
        this.usm = usm;
        this.usmMIB = usmMIB;
        this.vacmMIB = vacmMIB;
        this.dhKickstartParameters = dhKickstartParameters;
        moFactory = new SnmpUsmDHObjectsMibFactoryAdapter(moFactory);
        this.moFactory = moFactory;
        createMO(moFactory);
    }
//--AgentGen END

    /**
     * Create the ManagedObjects defined for this MIB module using the specified {@link MOFactory}.
     *
     * @param moFactory
     *         the {@code MOFactory} instance to use for object creation.
     */
    protected void createMO(MOFactory moFactory) {
        addTCsToFactory(moFactory);
        usmDHParameters =
                new UsmDHParameters(oidUsmDHParameters,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_WRITE));
        usmDHParameters.addMOValueValidationListener(new UsmDHParametersValidator());
        createUsmDHUserKeyEntry(moFactory);
        createUsmDHKickstartEntry(moFactory);
    }

    public UsmDHParametersImpl getUsmDHParameters() {
        return usmDHParameters;
    }


    @SuppressWarnings("rawtypes")
    public MOTable<UsmDHUserKeyEntryRow, MOColumn, MOTableModel<UsmDHUserKeyEntryRow>> getUsmDHUserKeyEntry() {
        return usmDHUserKeyEntry;
    }

    @SuppressWarnings("rawtypes")
    public void setBaseTableUsmDHUserKeyEntry(
            DefaultMOTable<UsmMIB.UsmTableRow, MOColumn, DefaultMOMutableTableModel<UsmMIB.UsmTableRow>> baseTable) {
        if (baseTable == null) {
            if (this.usmUserEntry != null && usmDHUserKeyEntryRelation != null) {
                this.usmUserEntry.removeMOTableRowListener(usmDHUserKeyEntryRelation.getRelationShipListener());
            }
        } else {
            this.usmUserEntry = baseTable;
            usmDHUserKeyEntryRelation = moFactory.createTableRelation(baseTable, usmDHUserKeyEntry);
            usmDHUserKeyEntryRelation.createRelationShip();
        }
    }

    @SuppressWarnings(value = {"unchecked"})
    private void createUsmDHUserKeyEntry(MOFactory moFactory) {
        // Index definition
        usmDHUserKeyEntryIndexes =
                new MOTableSubIndex[]{
                        moFactory.createSubIndex(oidUsmUserEngineID,
                                SMIConstants.SYNTAX_OCTET_STRING, 5, 32)
                        ,
                        moFactory.createSubIndex(oidUsmUserName,
                                SMIConstants.SYNTAX_OCTET_STRING, 1, 32)
                };

        usmDHUserKeyEntryIndex =
                moFactory.createIndex(usmDHUserKeyEntryIndexes,
                        false,
                        new MOTableIndexValidator() {
                            public boolean isValidIndex(OID index) {
                                boolean isValidIndex = true;
                                //--AgentGen BEGIN=usmDHUserKeyEntry::isValidIndex
                                //--AgentGen END
                                return isValidIndex;
                            }
                        });

        // Columns
        MOColumn<?>[] usmDHUserKeyEntryColumns = new MOColumn<?>[4];
        usmDHUserKeyEntryColumns[idxUsmDHUserAuthKeyChange] =
                new DHKeyChangeImpl(colUsmDHUserAuthKeyChange,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (OctetString) null
                        //--AgentGen BEGIN=usmDHUserAuthKeyChange::auxInit
                        , usmDHParameters.getDHParamters(), usmMIB, DHOperations.KeyType.authKeyChange
                        //--AgentGen END
                );
        usmDHUserKeyEntryColumns[idxUsmDHUserOwnAuthKeyChange] =
                new DHKeyChangeImpl(colUsmDHUserOwnAuthKeyChange,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (OctetString) null
                        //--AgentGen BEGIN=usmDHUserOwnAuthKeyChange::auxInit
                        , usmDHParameters.getDHParamters(), usmMIB, DHOperations.KeyType.authKeyChange
                        //--AgentGen END
                );
        usmDHUserKeyEntryColumns[idxUsmDHUserPrivKeyChange] =
                new DHKeyChangeImpl(colUsmDHUserPrivKeyChange,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (OctetString) null
                        //--AgentGen BEGIN=usmDHUserPrivKeyChange::auxInit
                        , usmDHParameters.getDHParamters(), usmMIB, DHOperations.KeyType.privKeyChange
                        //--AgentGen END
                );
        usmDHUserKeyEntryColumns[idxUsmDHUserOwnPrivKeyChange] =
                new DHKeyChangeImpl(colUsmDHUserOwnPrivKeyChange,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (OctetString) null
                        //--AgentGen BEGIN=usmDHUserOwnPrivKeyChange::auxInit
                        , usmDHParameters.getDHParamters(), usmMIB, DHOperations.KeyType.privKeyChange
                        //--AgentGen END
                );
        // Table model
        usmDHUserKeyEntryModel =
                moFactory.createTableModel(oidUsmDHUserKeyEntry,
                        usmDHUserKeyEntryIndex,
                        usmDHUserKeyEntryColumns);
        ((MOMutableTableModel<UsmDHUserKeyEntryRow>) usmDHUserKeyEntryModel).setRowFactory(
                new UsmDHUserKeyEntryRowFactory());
        usmDHUserKeyEntry =
                moFactory.createTable(oidUsmDHUserKeyEntry,
                        usmDHUserKeyEntryIndex,
                        usmDHUserKeyEntryColumns,
                        usmDHUserKeyEntryModel);
    }

    @SuppressWarnings("rawtypes")
    public MOTable<UsmDHKickstartEntryRow, MOColumn, MOTableModel<UsmDHKickstartEntryRow>> getUsmDHKickstartEntry() {
        return usmDHKickstartEntry;
    }


    @SuppressWarnings(value = {"unchecked"})
    private void createUsmDHKickstartEntry(MOFactory moFactory) {
        // Index definition
        usmDHKickstartEntryIndexes =
                new MOTableSubIndex[]{
                        moFactory.createSubIndex(oidUsmDHKickstartIndex,
                                SMIConstants.SYNTAX_INTEGER, 1, 1)};

        usmDHKickstartEntryIndex =
                moFactory.createIndex(usmDHKickstartEntryIndexes,
                        false,
                        new MOTableIndexValidator() {
                            public boolean isValidIndex(OID index) {
                                boolean isValidIndex = true;
                                //--AgentGen BEGIN=usmDHKickstartEntry::isValidIndex
                                //--AgentGen END
                                return isValidIndex;
                            }
                        });

        // Columns
        MOColumn<?>[] usmDHKickstartEntryColumns = new MOColumn<?>[3];
        usmDHKickstartEntryColumns[idxUsmDHKickstartMyPublic] =
                moFactory.createColumn(colUsmDHKickstartMyPublic,
                        SMIConstants.SYNTAX_OCTET_STRING,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY));
        usmDHKickstartEntryColumns[idxUsmDHKickstartMgrPublic] =
                moFactory.createColumn(colUsmDHKickstartMgrPublic,
                        SMIConstants.SYNTAX_OCTET_STRING,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY));
        usmDHKickstartEntryColumns[idxUsmDHKickstartSecurityName] =
                moFactory.createColumn(colUsmDHKickstartSecurityName,
                        SMIConstants.SYNTAX_OCTET_STRING,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_ONLY),
                        tcModuleSnmpFrameworkMib,
                        tcDefSnmpAdminString);
        // Table model
        usmDHKickstartEntryModel =
                moFactory.createTableModel(oidUsmDHKickstartEntry,
                        usmDHKickstartEntryIndex,
                        usmDHKickstartEntryColumns);
        ((MOMutableTableModel<UsmDHKickstartEntryRow>) usmDHKickstartEntryModel).setRowFactory(
                new UsmDHKickstartEntryRowFactory());
        usmDHKickstartEntry =
                moFactory.createTable(oidUsmDHKickstartEntry,
                        usmDHKickstartEntryIndex,
                        usmDHKickstartEntryColumns,
                        usmDHKickstartEntryModel);
        //--AgentGen BEGIN=usmDHKickstartEntry::createTable

        //--AgentGen END
    }


    public void registerMOs(MOServer server, OctetString context)
            throws DuplicateRegistrationException {
        // Scalar Objects
        server.register(this.usmDHParameters, context);
        server.register(this.usmDHUserKeyEntry, context);
        server.register(this.usmDHKickstartEntry, context);
//--AgentGen BEGIN=_registerMOs
        if (usmMIB != null) {
            setBaseTableUsmDHUserKeyEntry(usmMIB.getUsmUserEntry());
            if (this.dhKickstartParameters != null) {
                initDHKickstart(this.dhKickstartParameters);
            }
        }
//--AgentGen END
    }

    public void unregisterMOs(MOServer server, OctetString context) {
        // Scalar Objects
        server.unregister(this.usmDHParameters, context);
        server.unregister(this.usmDHUserKeyEntry, context);
        server.unregister(this.usmDHKickstartEntry, context);
//--AgentGen BEGIN=_unregisterMOs
        if (usmMIB != null) {
            setBaseTableUsmDHUserKeyEntry(null);
        }
        if (vacmMIB != null) {

        }
//--AgentGen END
    }

    // Notifications

    // Scalars
    public class UsmDHParameters extends UsmDHParametersImpl {
        UsmDHParameters(OID oid, MOAccess access) {
            super(oid, access, new OctetString());
//--AgentGen BEGIN=usmDHParameters
//--AgentGen END
        }

        public int isValueOK(SubRequest<?> request) {
            Variable newValue =
                    request.getVariableBinding().getVariable();
            int valueOK = super.isValueOK(request);
            if (valueOK != SnmpConstants.SNMP_ERROR_SUCCESS) {
                return valueOK;
            }
            //--AgentGen BEGIN=usmDHParameters::isValueOK
            //--AgentGen END
            return valueOK;
        }

        public OctetString getValue() {
            //--AgentGen BEGIN=usmDHParameters::getValue
            //--AgentGen END
            return super.getValue();
        }

        public int setValue(OctetString newValue) {
            //--AgentGen BEGIN=usmDHParameters::setValue
            try {
                decodeBER(newValue);
            } catch (IOException e) {
                return PDU.commitFailed;
            }
            //--AgentGen END
            return super.setValue(newValue);
        }

        //--AgentGen BEGIN=usmDHParameters::_METHODS
        //--AgentGen END

    }


    // Value Validators

    /**
     * The {@code UsmDHParametersValidator} implements the value validation for <code>UsmDHParametersImpl</code>.
     */
    static class UsmDHParametersValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            //--AgentGen BEGIN=usmDHParameters::validate
            if (newValue instanceof OctetString) {
                try {
                    DHParameters.getDHParametersFromBER((OctetString) newValue);
                } catch (IOException e) {
                    validationEvent.setValidationStatus(PDU.wrongEncoding);
                }
            } else {
                validationEvent.setValidationStatus(PDU.wrongType);
            }
            //--AgentGen END
        }
    }


    // Rows and Factories

    public class UsmDHUserKeyEntryRow extends DefaultMOMutableRow2PC {

        //--AgentGen BEGIN=usmDHUserKeyEntry::RowMembers
        private DHKeyInfo authKeyChange;
        private DHKeyInfo ownAuthKeyChange;
        private DHKeyInfo privKeyChange;
        private DHKeyInfo ownPrivKeyChange;
        //--AgentGen END

        public UsmDHUserKeyEntryRow(OID index, Variable[] values) {
            super(index, values);
            //--AgentGen BEGIN=usmDHUserKeyEntry::RowConstructor
            this.authKeyChange = new DHKeyInfo();
            this.ownAuthKeyChange = new DHKeyInfo();
            this.privKeyChange = new DHKeyInfo();
            this.ownPrivKeyChange = new DHKeyInfo();
            //--AgentGen END
        }

        public OctetString getUsmDHUserAuthKeyChange() {
            //--AgentGen BEGIN=usmDHUserKeyEntry::getUsmDHUserAuthKeyChange
            try {
                setValue(idxUsmDHUserAuthKeyChange,
                        new OctetString(((DHPublicKey) getAuthKeyChange().getKeyPair().getPublic()).getY().toByteArray()));
            } catch (NullPointerException npe) {
                setValue(idxUsmDHUserAuthKeyChange, new OctetString());
            }
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHUserAuthKeyChange);
        }

        public void setUsmDHUserAuthKeyChange(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::setUsmDHUserAuthKeyChange
            //--AgentGen END
            super.setValue(idxUsmDHUserAuthKeyChange, newColValue);
        }

        public OctetString getUsmDHUserOwnAuthKeyChange() {
            //--AgentGen BEGIN=usmDHUserKeyEntry::getUsmDHUserOwnAuthKeyChange
            try {
                setValue(idxUsmDHUserOwnAuthKeyChange,
                        new OctetString(((DHPublicKey) getOwnAuthKeyChange().getKeyPair().getPublic()).getY().toByteArray()));
            } catch (NullPointerException npe) {
                setValue(idxUsmDHUserOwnAuthKeyChange, new OctetString());
            }
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHUserOwnAuthKeyChange);
        }

        public void setUsmDHUserOwnAuthKeyChange(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::setUsmDHUserOwnAuthKeyChange
            //--AgentGen END
            super.setValue(idxUsmDHUserOwnAuthKeyChange, newColValue);
        }

        public OctetString getUsmDHUserPrivKeyChange() {
            //--AgentGen BEGIN=usmDHUserKeyEntry::getUsmDHUserPrivKeyChange
            try {
                setValue(idxUsmDHUserPrivKeyChange,
                        new OctetString(((DHPublicKey) getPrivKeyChange().getKeyPair().getPublic()).getY().toByteArray()));
            } catch (NullPointerException npe) {
                setValue(idxUsmDHUserPrivKeyChange, new OctetString());
            }
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHUserPrivKeyChange);
        }

        public void setUsmDHUserPrivKeyChange(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::setUsmDHUserPrivKeyChange
            //--AgentGen END
            super.setValue(idxUsmDHUserPrivKeyChange, newColValue);
        }

        public OctetString getUsmDHUserOwnPrivKeyChange() {
            //--AgentGen BEGIN=usmDHUserKeyEntry::getUsmDHUserOwnPrivKeyChange
            try {
                setValue(idxUsmDHUserOwnPrivKeyChange,
                        new OctetString(((DHPublicKey) getOwnPrivKeyChange().getKeyPair().getPublic()).getY().toByteArray()));
            } catch (NullPointerException npe) {
                setValue(idxUsmDHUserOwnPrivKeyChange, new OctetString());
            }
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHUserOwnPrivKeyChange);
        }

        public void setUsmDHUserOwnPrivKeyChange(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::setUsmDHUserOwnPrivKeyChange
            //--AgentGen END
            super.setValue(idxUsmDHUserOwnPrivKeyChange, newColValue);
        }

        public Variable getValue(int column) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::RowGetValue
            //--AgentGen END
            switch (column) {
                case idxUsmDHUserAuthKeyChange:
                    return getUsmDHUserAuthKeyChange();
                case idxUsmDHUserOwnAuthKeyChange:
                    return getUsmDHUserOwnAuthKeyChange();
                case idxUsmDHUserPrivKeyChange:
                    return getUsmDHUserPrivKeyChange();
                case idxUsmDHUserOwnPrivKeyChange:
                    return getUsmDHUserOwnPrivKeyChange();
                default:
                    return super.getValue(column);
            }
        }

        public void setValue(int column, Variable value) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::RowSetValue
            //--AgentGen END
            switch (column) {
                case idxUsmDHUserAuthKeyChange:
                    setUsmDHUserAuthKeyChange((OctetString) value);
                    break;
                case idxUsmDHUserOwnAuthKeyChange:
                    setUsmDHUserOwnAuthKeyChange((OctetString) value);
                    break;
                case idxUsmDHUserPrivKeyChange:
                    setUsmDHUserPrivKeyChange((OctetString) value);
                    break;
                case idxUsmDHUserOwnPrivKeyChange:
                    setUsmDHUserOwnPrivKeyChange((OctetString) value);
                    break;
                default:
                    super.setValue(column, value);
            }
        }

        //--AgentGen BEGIN=usmDHUserKeyEntry::Row

        public MOTableIndex getIndexDef() {
            return usmUserEntry.getIndexDef();
        }

        public AuthenticationProtocol getAuthProtocol(MOTableRow changeSet) {
            OID authOID = ((UsmTableRow) getBaseRow()).getAuthProtocolOID(changeSet);
            return usmMIB.getSecurityProtocols().getAuthenticationProtocol(authOID);
        }

        public PrivacyProtocol getPrivProtocol(MOTableRow changeSet) {
            OID privOID = ((UsmTableRow) getBaseRow()).getPrivProtocolOID(changeSet);
            return usmMIB.getSecurityProtocols().getPrivacyProtocol(privOID);
        }

        @Override
        public void commitRow(SubRequest<?> subRequest, MOTableRow changeSet) {
            super.commitRow(subRequest, changeSet);
            if (subRequest.getErrorStatus() == 0) {
                MOTableRow baseRow = getBaseRow();
                if (baseRow instanceof UsmTableRow) {
                    UsmTableRow usmTableRow = (UsmTableRow) baseRow;
                    if (isKeyChangePending()) {
                        DefaultMOMutableRow2PC changeSetBaseRow = new DefaultMOMutableRow2PC(baseRow.getIndex(),
                                new Variable[usmMIB.getUsmUserEntry().getColumnCount()]);
                        usmTableRow.commitRow(subRequest, changeSetBaseRow);
                        usmTableRow.clearKeyChangeObjects();
                    }
                }
            }
        }

        public DHKeyInfo getAuthKeyChange() {
            return authKeyChange;
        }

        public DHKeyInfo getOwnAuthKeyChange() {
            return ownAuthKeyChange;
        }

        public DHKeyInfo getPrivKeyChange() {
            return privKeyChange;
        }

        public DHKeyInfo getOwnPrivKeyChange() {
            return ownPrivKeyChange;
        }

        public byte[] getNewAuthKey() {
            if (authKeyChange.getUsmKey() != null) {
                return authKeyChange.getUsmKey();
            } else if (ownAuthKeyChange.getUsmKey() != null) {
                return ownAuthKeyChange.getUsmKey();
            }
            return null;
        }

        public byte[] getNewPrivKey() {
            if (privKeyChange.getUsmKey() != null) {
                return privKeyChange.getUsmKey();
            } else if (ownPrivKeyChange.getUsmKey() != null) {
                return ownPrivKeyChange.getUsmKey();
            }
            return null;
        }

        public void clearDHKeyChange() {
            authKeyChange.clearUsmKey();
            ownAuthKeyChange.clearUsmKey();
            privKeyChange.clearUsmKey();
            ownPrivKeyChange.clearUsmKey();
        }

        public boolean isKeyChangePending() {
            return authKeyChange.isKeyChangePending() || ownAuthKeyChange.isKeyChangePending() ||
                    privKeyChange.isKeyChangePending() || ownPrivKeyChange.isKeyChangePending();
        }

        //--AgentGen END
    }

    class UsmDHUserKeyEntryRowFactory
            implements MOTableRowFactory<UsmDHUserKeyEntryRow> {
        public synchronized UsmDHUserKeyEntryRow createRow(OID index, Variable[] values)
                throws UnsupportedOperationException {
            UsmDHUserKeyEntryRow row =
                    new UsmDHUserKeyEntryRow(index, values);
            //--AgentGen BEGIN=usmDHUserKeyEntry::createRow
            //--AgentGen END
            return row;
        }

        public synchronized void freeRow(UsmDHUserKeyEntryRow row) {
            //--AgentGen BEGIN=usmDHUserKeyEntry::freeRow
            //--AgentGen END
        }

        //--AgentGen BEGIN=usmDHUserKeyEntry::RowFactory
        //--AgentGen END
    }

    public class UsmDHKickstartEntryRow extends DefaultMOMutableRow2PC {

        //--AgentGen BEGIN=usmDHKickstartEntry::RowMembers
        //--AgentGen END

        public UsmDHKickstartEntryRow(OID index, Variable[] values) {
            super(index, values);
            //--AgentGen BEGIN=usmDHKickstartEntry::RowConstructor
            //--AgentGen END
        }

        public OctetString getUsmDHKickstartMyPublic() {
            //--AgentGen BEGIN=usmDHKickstartEntry::getUsmDHKickstartMyPublic
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHKickstartMyPublic);
        }

        public void setUsmDHKickstartMyPublic(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHKickstartEntry::setUsmDHKickstartMyPublic
            //--AgentGen END
            super.setValue(idxUsmDHKickstartMyPublic, newColValue);
        }

        public OctetString getUsmDHKickstartMgrPublic() {
            //--AgentGen BEGIN=usmDHKickstartEntry::getUsmDHKickstartMgrPublic
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHKickstartMgrPublic);
        }

        public void setUsmDHKickstartMgrPublic(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHKickstartEntry::setUsmDHKickstartMgrPublic
            //--AgentGen END
            super.setValue(idxUsmDHKickstartMgrPublic, newColValue);
        }

        public OctetString getUsmDHKickstartSecurityName() {
            //--AgentGen BEGIN=usmDHKickstartEntry::getUsmDHKickstartSecurityName
            //--AgentGen END
            return (OctetString) super.getValue(idxUsmDHKickstartSecurityName);
        }

        public void setUsmDHKickstartSecurityName(OctetString newColValue) {
            //--AgentGen BEGIN=usmDHKickstartEntry::setUsmDHKickstartSecurityName
            //--AgentGen END
            super.setValue(idxUsmDHKickstartSecurityName, newColValue);
        }

        public Variable getValue(int column) {
            //--AgentGen BEGIN=usmDHKickstartEntry::RowGetValue
            //--AgentGen END
            switch (column) {
                case idxUsmDHKickstartMyPublic:
                    return getUsmDHKickstartMyPublic();
                case idxUsmDHKickstartMgrPublic:
                    return getUsmDHKickstartMgrPublic();
                case idxUsmDHKickstartSecurityName:
                    return getUsmDHKickstartSecurityName();
                default:
                    return super.getValue(column);
            }
        }

        public void setValue(int column, Variable value) {
            //--AgentGen BEGIN=usmDHKickstartEntry::RowSetValue
            //--AgentGen END
            switch (column) {
                case idxUsmDHKickstartMyPublic:
                    setUsmDHKickstartMyPublic((OctetString) value);
                    break;
                case idxUsmDHKickstartMgrPublic:
                    setUsmDHKickstartMgrPublic((OctetString) value);
                    break;
                case idxUsmDHKickstartSecurityName:
                    setUsmDHKickstartSecurityName((OctetString) value);
                    break;
                default:
                    super.setValue(column, value);
            }
        }

        //--AgentGen BEGIN=usmDHKickstartEntry::Row
        //--AgentGen END
    }

    class UsmDHKickstartEntryRowFactory
            implements MOTableRowFactory<UsmDHKickstartEntryRow> {
        public synchronized UsmDHKickstartEntryRow createRow(OID index, Variable[] values)
                throws UnsupportedOperationException {
            UsmDHKickstartEntryRow row =
                    new UsmDHKickstartEntryRow(index, values);
            //--AgentGen BEGIN=usmDHKickstartEntry::createRow
            //--AgentGen END
            return row;
        }

        public synchronized void freeRow(UsmDHKickstartEntryRow row) {
            //--AgentGen BEGIN=usmDHKickstartEntry::freeRow
            //--AgentGen END
        }

        //--AgentGen BEGIN=usmDHKickstartEntry::RowFactory
        //--AgentGen END
    }


//--AgentGen BEGIN=_METHODS

    public DHParameters getDHParameters() {
        try {
            return DHParameters.getDHParametersFromBER(new OctetString(usmDHParameters.getValue()));
        } catch (IOException e) {
            LOGGER.error("Unable to decode usmDHParameters value '" + usmDHParameters.getValue().toHexString() + "'", e);
            return null;
        }
    }

    protected void initDHKickstart(Collection<DHKickstartParameters> dhKickstartParametersList) {
        int kickStartRowIndex = 1;
        for (DHKickstartParameters dhKickstartParameters : dhKickstartParametersList) {
            try {
                OID authProtocol = SnmpConstants.usmHMACMD5AuthProtocol;
                if (dhKickstartParameters.getAuthenticationProtocol() != null) {
                    authProtocol = dhKickstartParameters.getAuthenticationProtocol();
                }
                OID privProtocol = SnmpConstants.usmDESPrivProtocol;
                if (dhKickstartParameters.getPrivacyProtocol() != null) {
                    privProtocol = dhKickstartParameters.getPrivacyProtocol();
                }
                DHParameters dhParameters = getDHParameters();

                KeyPair keyPair = DHOperations.generatePublicKey(dhParameters);
                KeyAgreement keyAgreement = DHOperations.getInitializedKeyAgreement(keyPair);
                byte[] sharedKey =
                        DHOperations.computeSharedKey(keyAgreement, dhKickstartParameters.getPublicKey().getValue(), dhParameters);
                AuthenticationProtocol authenticationProtocol =
                        SecurityProtocols.getInstance().getAuthenticationProtocol(authProtocol);
                if (authenticationProtocol == null) {
                    LOGGER.warn("Unknown authentication protocol '"+authProtocol+
                            " for kickstart DH key exchange: "+dhKickstartParameters);
                    continue;
                }
                OctetString authKey =
                        new OctetString(DHOperations.deriveKeyPBKDF2(sharedKey, authenticationProtocol.getDigestLength(),
                                SecurityProtocols.SecurityProtocolType.authentication));
                PrivacyProtocol privacyProtocol = SecurityProtocols.getInstance().getPrivacyProtocol(privProtocol);
                if (privacyProtocol == null) {
                    LOGGER.warn("Unknown privacy protocol '"+privProtocol+
                            " for kickstart DH key exchange: "+dhKickstartParameters);
                    continue;
                }
                OctetString privKey =
                        new OctetString(DHOperations.deriveKeyPBKDF2(sharedKey, privacyProtocol.getMaxKeyLength(),
                                SecurityProtocols.SecurityProtocolType.privacy));
                UsmUserEntry usmUserEntry = new UsmUserEntry(dhKickstartParameters.getSecurityName(), usm.getLocalEngineID(),
                        new UsmUser(dhKickstartParameters.getSecurityName(), authProtocol, authKey,
                                privProtocol, privKey, usm.getLocalEngineID()));
                usmUserEntry.setStorageType(SnmpConstants.StorageTypeEnum.permanent);
                usm.getUserTable().addUser(usmUserEntry);
                if (usm.getUserTable().getUser(dhKickstartParameters.getSecurityName()) == null ||
                        dhKickstartParameters.isResetRequested()) {
                    usm.addUsmUserEntry(usmUserEntry);

                    UsmDHKickstartEntryRow kickstartEntryRow =
                          usmDHKickstartEntry.addNewRow(new OID(new int[] { kickStartRowIndex++ }), new Variable[] {
                                  DHOperations.derivePublicKey(keyPair), dhKickstartParameters.getPublicKey(),
                                  dhKickstartParameters.getSecurityName()
                          });
                    if (kickstartEntryRow == null) {
                        LOGGER.warn("USM kickstart row not created for '"+dhKickstartParameters.getSecurityName()+"'");
                    }
                    else {
                        if (dhKickstartParameters.getVacmRole() != null) {
                            vacmMIB.addGroup(SnmpConstants.version3, dhKickstartParameters.getSecurityName(),
                                    getGroupNameForVacmRole(dhKickstartParameters.getVacmRole()),
                                    SnmpConstants.StorageTypeEnum.permanent.getSmiValue());
                        }
                    }
                } else {
                    LOGGER.warn("USM kickstart user " + dhKickstartParameters + " not created because security name already exists");
                }
            } catch (Exception ex) {
                LOGGER.error("Unable to kickstart Diffie Hellman USM key exchange for " + dhKickstartParameters, ex);
                ex.printStackTrace();
            }
        }
        OctetString dhKickstart = new OctetString(DHOperations.DH_KICKSTART_SEC_NAME);
        OctetString dhKickstartReadView = new OctetString(DHOperations.DH_KICKSTART_VIEW_NAME);
        usm.getUserTable().addUser(new UsmUserEntry(dhKickstart,
                new UsmUser(dhKickstart,
                        SnmpConstants.usmNoAuthProtocol, null,
                        SnmpConstants.usmNoPrivProtocol, null)));
        vacmMIB.addGroup(SnmpConstants.version3, dhKickstart, dhKickstart, SnmpConstants.StorageTypeEnum.permanent.getSmiValue());
        vacmMIB.addAccess(dhKickstart, null, SecurityModel.SECURITY_MODEL_USM, SecurityLevel.NOAUTH_NOPRIV,
                MutableVACM.VACM_MATCH_PREFIX, dhKickstartReadView, null, dhKickstartReadView,
                SnmpConstants.StorageTypeEnum.permanent.getSmiValue());
        vacmMIB.addViewTreeFamily(dhKickstartReadView, SnmpConstants.system, new OctetString(),
                MutableVACM.VACM_VIEW_INCLUDED, SnmpConstants.StorageTypeEnum.permanent.getSmiValue());
        vacmMIB.addViewTreeFamily(dhKickstartReadView, oidUsmDHKickstartEntry, new OctetString(),
                MutableVACM.VACM_VIEW_INCLUDED, SnmpConstants.StorageTypeEnum.permanent.getSmiValue());
    }

    /**
     * Return the VACM group name for the specified VACM role.
     *
     * @param role
     *         a role name.
     *
     * @return the group name for the role. By default, the role is returned as {@link OctetString}.
     */
    protected OctetString getGroupNameForVacmRole(String role) {
        return new OctetString(role);
    }
//--AgentGen END

    // Textual Definitions of MIB module SnmpUsmDhObjectsMib
    protected void addTCsToFactory(MOFactory moFactory) {
        moFactory.addTextualConvention(new DHKeyChange());
    }


    public class DHKeyChange implements TextualConvention<OctetString> {

        public DHKeyChange() {
        }

        public String getModuleName() {
            return TC_MODULE_SNMP_USM_DH_OBJECTS_MIB;
        }

        public String getName() {
            return TC_DHKEYCHANGE;
        }

        public OctetString createInitialValue() {
            OctetString v = new OctetString();
            // further modify value to comply with TC constraints here:
            //--AgentGen BEGIN=DHKeyChangeImpl::createInitialValue
            //--AgentGen END
            return v;
        }

        public MOScalar<OctetString> createScalar(OID oid, MOAccess access, OctetString value) {
            MOScalar<OctetString> scalar = moFactory.createScalar(oid, access, value);
            //--AgentGen BEGIN=DHKeyChangeImpl::createScalar
            //--AgentGen END
            return scalar;
        }

        public MOColumn<OctetString> createColumn(int columnID, int syntax, MOAccess access,
                                                  OctetString defaultValue, boolean mutableInService) {
            MOColumn<OctetString> col = moFactory.createColumn(columnID, syntax, access,
                    defaultValue, mutableInService);
            //--AgentGen BEGIN=DHKeyChangeImpl::createColumn
            DHOperations.KeyType keyType = DHOperations.KeyType.authKeyChange;
            if (columnID >= colUsmDHUserPrivKeyChange) {
                keyType = DHOperations.KeyType.privKeyChange;
            }
            col = new DHKeyChangeImpl(columnID, access, defaultValue, getDHParameters(), usmMIB, keyType);
            //--AgentGen END
            return col;
        }
    }


//--AgentGen BEGIN=_TC_CLASSES_IMPORTED_MODULES_BEGIN
//--AgentGen END

    // Textual Definitions of other MIB modules
    public void addImportedTCsToFactory(MOFactory moFactory) {
        moFactory.addTextualConvention(new SnmpAdminStringTC());
    }

//--AgentGen BEGIN=_TC_CLASSES_IMPORTED_MODULES_END
//--AgentGen END

    //--AgentGen BEGIN=_CLASSES
    private class SnmpUsmDHObjectsMibFactoryAdapter extends MOFactoryAdapter {

        public SnmpUsmDHObjectsMibFactoryAdapter(MOFactory moFactory) {
            super(moFactory);
        }

        @Override
        @SuppressWarnings("rawtypes")
        public <BaseRow extends MOTableRow, DependentRow extends MOTableRow> MOTableRelation<BaseRow, DependentRow>
        createTableRelation(MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> baseTable,
                            MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> dependentTable) {
            return new MOTableRelation<BaseRow, DependentRow>(baseTable, dependentTable) {
                @Override
                public boolean hasDependentRow(BaseRow baseTableRow) {
                    return true;
                }
            };
        }
    }
//--AgentGen END

//--AgentGen BEGIN=_END
//--AgentGen END
}


