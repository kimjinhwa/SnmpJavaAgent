/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - Snmp4jConfigMib.java  
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


package org.snmp4j.agent.mo.snmp4j;

//--AgentGen BEGIN=_BEGIN
//--AgentGen END

import org.snmp4j.PDU;
import org.snmp4j.agent.*;
import org.snmp4j.agent.io.MOPersistenceProvider;
import org.snmp4j.agent.mo.*;
import org.snmp4j.agent.mo.snmp.*;
import org.snmp4j.agent.mo.snmp.smi.EnumerationConstraint;
import org.snmp4j.agent.mo.snmp.smi.ValueConstraint;
import org.snmp4j.agent.mo.snmp.smi.ValueConstraintValidator;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;

import java.io.File;
import java.util.*;

//--AgentGen BEGIN=_IMPORT
//--AgentGen END

public class Snmp4jConfigMib
//--AgentGen BEGIN=_EXTENDS
//--AgentGen END
        implements MOGroup
//--AgentGen BEGIN=_IMPLEMENTS
        , MOPriorityProvider
//--AgentGen END
{

    private static final LogAdapter logger =
            LogFactory.getLogger(Snmp4jConfigMib.class);

    // Factory
    private static MOFactory moFactory = DefaultMOFactory.getInstance();

    // Constants
    public static final OID oidSnmp4jCfgSecSrcAddrValidation =
            new OID(new int[]{1, 3, 6, 1, 4, 1, 4976, 10, 1, 1, 2, 1, 1, 1, 0});
    public static final OID oidSnmp4jCfgReset =
            new OID(new int[]{1, 3, 6, 1, 4, 1, 4976, 10, 1, 1, 2, 1, 3, 1, 0});

    // Scalars
    private MOScalar<Integer32> snmp4jCfgSecSrcAddrValidation;
    private MOScalar<Integer32> snmp4jCfgReset;

    // Tables
    public static final OID oidSnmp4jCfgStorageEntry =
            new OID(new int[]{1, 3, 6, 1, 4, 1, 4976, 10, 1, 1, 2, 1, 2, 1, 1});

    // Column sub-identifier definitions for snmp4jCfgStorageEntry:
    public static final int colSnmp4jCfgStoragePath = 2;
    public static final int colSnmp4jCfgStorageID = 10;
    public static final int colSnmp4jCfgStorageLastStore = 4;
    public static final int colSnmp4jCfgStorageLastRestore = 5;
    public static final int colSnmp4jCfgStorageRestoreMode = 6;
    public static final int colSnmp4jCfgStorageOperation = 7;
    public static final int colSnmp4jCfgStorageStorageType = 8;
    public static final int colSnmp4jCfgStorageStatus = 9;

    // Column index definitions for snmp4jCfgStorageEntry:
    public static final int idxSnmp4jCfgStoragePath = 0;
    public static final int idxSnmp4jCfgStorageID = 7;
    public static final int idxSnmp4jCfgStorageLastStore = 1;
    public static final int idxSnmp4jCfgStorageLastRestore = 2;
    public static final int idxSnmp4jCfgStorageRestoreMode = 3;
    public static final int idxSnmp4jCfgStorageOperation = 4;
    public static final int idxSnmp4jCfgStorageStorageType = 5;
    public static final int idxSnmp4jCfgStorageStatus = 6;
    private static MOTableSubIndex[] snmp4jCfgStorageEntryIndexes =
            new MOTableSubIndex[]{
                    moFactory.createSubIndex(null, SMIConstants.SYNTAX_OCTET_STRING, 0, 255)
            };

    private static MOTableIndex snmp4jCfgStorageEntryIndex =
            moFactory.createIndex(snmp4jCfgStorageEntryIndexes,
                    false);

    @SuppressWarnings("rawtypes")
    private MOTable<Snmp4jCfgStorageEntryRow, MOColumn, MOMutableTableModel<Snmp4jCfgStorageEntryRow>>
            snmp4jCfgStorageEntry;
    private MOMutableTableModel<Snmp4jCfgStorageEntryRow> snmp4jCfgStorageEntryModel;
    public static final OID oidSnmp4jCfgStorageSeqEntry =
            new OID(new int[]{1, 3, 6, 1, 4, 1, 4976, 10, 1, 1, 2, 1, 2, 2, 1});

    // Index OID definitions
    public static final OID oidSnmp4jCfgStorageSeqIndex =
            new OID(new int[]{1, 3, 6, 1, 4, 1, 4976, 10, 1, 1, 2, 1, 2, 2, 1, 1});

    // Column TC definitions for snmp4jCfgStorageSeqEntry:

    // Column sub-identifier definitions for snmp4jCfgStorageSeqEntry:
    public static final int colSnmp4jCfgStorageSeqSubtree = 2;
    public static final int colSnmp4jCfgStorageSeqStorageType = 3;
    public static final int colSnmp4jCfgStorageSeqRowStatus = 4;

    // Column index definitions for snmp4jCfgStorageSeqEntry:
    public static final int idxSnmp4jCfgStorageSeqSubtree = 0;
    public static final int idxSnmp4jCfgStorageSeqStorageType = 1;
    public static final int idxSnmp4jCfgStorageSeqRowStatus = 2;

    private MOTableSubIndex[] snmp4jCfgStorageSeqEntryIndexes;
    private MOTableIndex snmp4jCfgStorageSeqEntryIndex;

    @SuppressWarnings(value = {"rawtypes"})
    private MOTable<
            Snmp4jCfgStorageSeqEntryRow, MOColumn, MOMutableTableModel<Snmp4jCfgStorageSeqEntryRow>>
            snmp4jCfgStorageSeqEntry;

    private MOMutableTableModel<Snmp4jCfgStorageSeqEntryRow> snmp4jCfgStorageSeqEntryModel;

    //--AgentGen BEGIN=_MEMBERS
    public static final OID PRIMARY_INDEX =
            new OctetString("primary").toSubIndex(false);

    protected SnmpCommunityMIB snmpCommunityMIB;
    protected Map<CharSequence, MOPersistenceProvider> persistenceProvider = new LinkedHashMap<CharSequence, MOPersistenceProvider>();
    protected MOPersistenceProvider primaryPersistence;
    protected SysUpTime sysUpTime;

    private File configPathRoot;

    private AgentConfigManager agentConfigManager;

//--AgentGen END

    public Snmp4jConfigMib(SysUpTime sysUpTime) {
        this.sysUpTime = sysUpTime;
        snmp4jCfgSecSrcAddrValidation =
                new Snmp4jCfgSecSrcAddrValidation(oidSnmp4jCfgSecSrcAddrValidation, MOAccessImpl.ACCESS_READ_WRITE);
        snmp4jCfgReset = new Snmp4jCfgReset(oidSnmp4jCfgReset, MOAccessImpl.ACCESS_READ_WRITE);
        createSnmp4jCfgStorageEntry();
        configPathRoot = new File(System.getProperty("user.dir", ""));
    }

    public Snmp4jConfigMib(SysUpTime sysUpTime, AgentConfigManager agentConfigManager) {
        this(sysUpTime);
        this.agentConfigManager = agentConfigManager;
    }

    @SuppressWarnings("rawtypes")
    public MOTable<Snmp4jCfgStorageEntryRow, MOColumn, MOMutableTableModel<Snmp4jCfgStorageEntryRow>>
    getSnmp4jCfgStorageEntry() {
        return snmp4jCfgStorageEntry;
    }

    public MOPersistenceProvider getPrimaryPersistence() {
        return primaryPersistence;
    }

    @SuppressWarnings("unchecked")
    private void createSnmp4jCfgStorageEntry() {
        MOColumn<?>[] snmp4jCfgStorageEntryColumns = new MOColumn<?>[8];
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStoragePath] =
                new DisplayString<OctetString>(colSnmp4jCfgStoragePath,
                        MOAccessImpl.ACCESS_READ_CREATE,
                        null,
                        true,
                        0, 255);
        ((MOMutableColumn<?>) snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStoragePath]).
                addMOValueValidationListener(new Snmp4jCfgStoragePathValidator());
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageID] =
                new MOMutableColumn<>(colSnmp4jCfgStorageID,
                        SMIConstants.SYNTAX_OCTET_STRING,
                        MOAccessImpl.ACCESS_READ_CREATE,
                        new OctetString("default"));
        ((MOMutableColumn<?>) snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageID]).
                addMOValueValidationListener(new Snmp4jCfgStorageFormatValidator());
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageLastStore] =
                new MOColumn<>(colSnmp4jCfgStorageLastStore,
                        SMIConstants.SYNTAX_TIMETICKS,
                        MOAccessImpl.ACCESS_READ_ONLY);
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageLastRestore] =
                new MOColumn<>(colSnmp4jCfgStorageLastRestore,
                        SMIConstants.SYNTAX_TIMETICKS,
                        MOAccessImpl.ACCESS_READ_ONLY);
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageRestoreMode] =
                new Enumerated<>(colSnmp4jCfgStorageRestoreMode,
                        SMIConstants.SYNTAX_INTEGER32,
                        MOAccessImpl.ACCESS_READ_CREATE,
                        new Integer32(1),
                        true,
                        new int[]{Snmp4jCfgStorageRestoreModeEnum.replaceAndCreate,
                                Snmp4jCfgStorageRestoreModeEnum.updateAndCreate,
                                Snmp4jCfgStorageRestoreModeEnum.updateOnly,
                                Snmp4jCfgStorageRestoreModeEnum.createOnly});
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageOperation] =
                new Enumerated<>(colSnmp4jCfgStorageOperation,
                        SMIConstants.SYNTAX_INTEGER32,
                        MOAccessImpl.ACCESS_READ_CREATE,
                        new Integer32(1),
                        true,
                        new int[]{Snmp4jCfgStorageOperationEnum.idle,
                                Snmp4jCfgStorageOperationEnum.inProgress,
                                Snmp4jCfgStorageOperationEnum.store,
                                Snmp4jCfgStorageOperationEnum.restore});
        ((MOMutableColumn) snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageOperation]).
                addMOValueValidationListener(new Snmp4jCfgStorageOperationValidator());
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageStorageType] =
                new StorageType(colSnmp4jCfgStorageStorageType,
                        MOAccessImpl.ACCESS_READ_CREATE,
                        new Integer32(3),
                        true);
        snmp4jCfgStorageEntryColumns[idxSnmp4jCfgStorageStatus] =
                new RowStatus<Snmp4jCfgStorageEntryRow>(colSnmp4jCfgStorageStatus);

        snmp4jCfgStorageEntryModel = new DefaultMOMutableTableModel<>();
        snmp4jCfgStorageEntryModel.setRowFactory(new Snmp4jCfgStorageEntryRowFactory());
        snmp4jCfgStorageEntry =
                moFactory.createTable(oidSnmp4jCfgStorageEntry,
                        snmp4jCfgStorageEntryIndex,
                        snmp4jCfgStorageEntryColumns,
                        snmp4jCfgStorageEntryModel);
        createSnmp4jCfgStorageSeqEntry(moFactory);
    }

    @SuppressWarnings(value = {"rawtypes"})
    public MOTable<
            Snmp4jCfgStorageSeqEntryRow, MOColumn, MOMutableTableModel<Snmp4jCfgStorageSeqEntryRow>>
    getSnmp4jCfgStorageSeqEntry() {
        return snmp4jCfgStorageSeqEntry;
    }

    @SuppressWarnings(value = {"unchecked"})
    private void createSnmp4jCfgStorageSeqEntry(MOFactory moFactory) {
        // Index definition
        snmp4jCfgStorageSeqEntryIndexes =
                new MOTableSubIndex[]{
                        moFactory.createSubIndex(oidSnmp4jCfgStorageSeqIndex, SMIConstants.SYNTAX_INTEGER, 1, 1)
                };

        snmp4jCfgStorageSeqEntryIndex =
                moFactory.createIndex(
                        snmp4jCfgStorageSeqEntryIndexes,
                        false,
                        new MOTableIndexValidator() {
                            public boolean isValidIndex(OID index) {
                                boolean isValidIndex = true;
                                // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::isValidIndex
                                // --AgentGen END
                                return isValidIndex;
                            }
                        });

        // Columns
        MOColumn<?>[] snmp4jCfgStorageSeqEntryColumns = new MOColumn<?>[3];
        snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqSubtree] =
                new MOMutableColumn<OID>(
                        colSnmp4jCfgStorageSeqSubtree,
                        SMIConstants.SYNTAX_OBJECT_IDENTIFIER,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (OID) null
                        // --AgentGen BEGIN=snmp4jCfgStorageSeqSubtree::auxInit
                        // --AgentGen END
                );
        ((MOMutableColumn<?>) snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqSubtree])
                .addMOValueValidationListener(new Snmp4jCfgStorageSeqSubtreeValidator());
        snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqStorageType] =
                new StorageType(
                        colSnmp4jCfgStorageSeqStorageType,
                        moFactory.createAccess(MOAccessImpl.ACCESSIBLE_FOR_READ_CREATE),
                        (Integer32) null
                        // --AgentGen BEGIN=snmp4jCfgStorageSeqStorageType::auxInit
                        // --AgentGen END
                );
        ValueConstraint snmp4jCfgStorageSeqStorageTypeVC =
                new EnumerationConstraint(new int[]{1, 2, 3, 4, 5});
        ((MOMutableColumn<?>) snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqStorageType])
                .addMOValueValidationListener(
                        new ValueConstraintValidator(snmp4jCfgStorageSeqStorageTypeVC));
        ((MOMutableColumn<?>) snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqStorageType])
                .addMOValueValidationListener(new Snmp4jCfgStorageSeqStorageTypeValidator());
        snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqRowStatus] =
                new RowStatus(
                        colSnmp4jCfgStorageSeqRowStatus
                        // --AgentGen BEGIN=snmp4jCfgStorageSeqRowStatus::auxInit
                        // --AgentGen END
                );
        ValueConstraint snmp4jCfgStorageSeqRowStatusVC =
                new EnumerationConstraint(new int[]{1, 2, 3, 4, 5, 6});
        ((MOMutableColumn<?>) snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqRowStatus])
                .addMOValueValidationListener(new ValueConstraintValidator(snmp4jCfgStorageSeqRowStatusVC));
        ((MOMutableColumn<?>) snmp4jCfgStorageSeqEntryColumns[idxSnmp4jCfgStorageSeqRowStatus])
                .addMOValueValidationListener(new Snmp4jCfgStorageSeqRowStatusValidator());
        // Table model
        snmp4jCfgStorageSeqEntryModel =
                moFactory.createTableModel(
                        oidSnmp4jCfgStorageSeqEntry,
                        snmp4jCfgStorageSeqEntryIndex,
                        snmp4jCfgStorageSeqEntryColumns);
        ((MOMutableTableModel<Snmp4jCfgStorageSeqEntryRow>) snmp4jCfgStorageSeqEntryModel)
                .setRowFactory(new Snmp4jCfgStorageSeqEntryRowFactory());
        snmp4jCfgStorageSeqEntry =
                moFactory.createTable(
                        oidSnmp4jCfgStorageSeqEntry,
                        snmp4jCfgStorageSeqEntryIndex,
                        snmp4jCfgStorageSeqEntryColumns,
                        snmp4jCfgStorageSeqEntryModel);
    }

    public void registerMOs(MOServer server, OctetString context)
            throws DuplicateRegistrationException {
        // Scalar Objects
        server.register(this.snmp4jCfgSecSrcAddrValidation, context);
        if (agentConfigManager != null) {
            server.register(this.snmp4jCfgReset, context);
        }
        server.register(this.snmp4jCfgStorageEntry, context);
        server.register(this.snmp4jCfgStorageSeqEntry, context);
//--AgentGen BEGIN=_registerMOs
//--AgentGen END
    }

    public void unregisterMOs(MOServer server, OctetString context) {
        // Scalar Objects
        server.unregister(this.snmp4jCfgSecSrcAddrValidation, context);
        server.unregister(this.snmp4jCfgReset, context);
        server.unregister(this.snmp4jCfgStorageEntry, context);
        server.unregister(this.snmp4jCfgStorageSeqEntry, context);
//--AgentGen BEGIN=_unregisterMOs
//--AgentGen END
    }

    @Override
    public SortedMap<OID, Integer> getPriorityMap(OctetString context) {
        TreeMap<OID, Integer> priorityMap = new TreeMap<>();
        for (Iterator<Snmp4jCfgStorageSeqEntryRow> it = this.getSnmp4jCfgStorageSeqEntry().getModel().iterator(); it.hasNext(); ) {
            Snmp4jCfgStorageSeqEntryRow row = it.next();
            if (row.getSnmp4jCfgStorageSeqRowStatus().getValue() == RowStatus.active) {
                priorityMap.put(row.getSnmp4jCfgStorageSeqSubtree(), row.getIndex().get(0));
            }
        }
        return priorityMap;
    }

    /**
     * This default implementation of {@link MOPriorityProvider} does not support context depend configurations.
     * Thus it will return for all contexts {@link #getSnmp4jCfgStorageEntry()}.
     * @return
     *    {@link #getSnmp4jCfgStorageEntry()}
     */
    @Override
    public ManagedObject<?> getBootManagedObject(OctetString context) {
        return getSnmp4jCfgStorageSeqEntry();
    }

    // Notifications

    // Scalars
    public class Snmp4jCfgSecSrcAddrValidation extends EnumeratedScalar<Integer32> {
        Snmp4jCfgSecSrcAddrValidation(OID oid, MOAccess access) {
            super(oid, access, new Integer32(),
                    new int[]{Snmp4jCfgSecSrcAddrValidationEnum.enabled,
                            Snmp4jCfgSecSrcAddrValidationEnum.disabled,
                            Snmp4jCfgSecSrcAddrValidationEnum.notAvailable});
//--AgentGen BEGIN=snmp4jCfgSecSrcAddrValidation
//--AgentGen END
        }

        public Integer32 getValue() {
            if (snmpCommunityMIB != null) {
                if (snmpCommunityMIB.isSourceAddressFiltering()) {
                    setValue(new Integer32(Snmp4jCfgSecSrcAddrValidationEnum.enabled));
                } else {
                    setValue(new Integer32(Snmp4jCfgSecSrcAddrValidationEnum.disabled));
                }
            } else {
                setValue(new Integer32(Snmp4jCfgSecSrcAddrValidationEnum.notAvailable));
            }
            return (Integer32) super.getValue().clone();
        }

        public void commit(SubRequest<?> request) {
            //--AgentGen BEGIN=snmp4jCfgSecSrcAddrValidation::commit
            Integer32 newValue =
                    (Integer32) request.getVariableBinding().getVariable();
            switch (newValue.getValue()) {
                case Snmp4jCfgSecSrcAddrValidationEnum.disabled:
                    snmpCommunityMIB.setSourceAddressFiltering(false);
                    break;
                case Snmp4jCfgSecSrcAddrValidationEnum.enabled:
                    snmpCommunityMIB.setSourceAddressFiltering(true);
                    break;
                default:
                    request.getRequest().setErrorStatus(PDU.commitFailed);
            }
            //--AgentGen END
            super.commit(request);
        }

        public void cleanup(SubRequest<?> request) {
            //--AgentGen BEGIN=snmp4jCfgSecSrcAddrValidation::cleanup
            //--AgentGen END
            super.cleanup(request);
        }

        public int isValueOK(SubRequest<?> request) {
            Variable newValue =
                    request.getVariableBinding().getVariable();
            //--AgentGen BEGIN=snmp4jCfgSecSrcAddrValidation::isValueOK
            if (snmpCommunityMIB != null) {
                switch (((Integer32) newValue).getValue()) {
                    case Snmp4jCfgSecSrcAddrValidationEnum.disabled:
                    case Snmp4jCfgSecSrcAddrValidationEnum.enabled:
                        break;
                    default:
                        return PDU.wrongValue;
                }
            } else if (((Integer32) newValue).getValue() !=
                    Snmp4jCfgSecSrcAddrValidationEnum.notAvailable) {
                return PDU.inconsistentValue;
            } else {
                return PDU.wrongValue;
            }
            //--AgentGen END
            return super.isValueOK(request);
        }
    }

    public class Snmp4jCfgReset extends EnumeratedScalar<Integer32> {
        Snmp4jCfgReset(OID oid, MOAccess access) {
            super(oid, access, new Integer32(Snmp4jCfgResetEnum.idle),
                    new int[]{Snmp4jCfgResetEnum.idle, Snmp4jCfgResetEnum.factoryReset});
            //--AgentGen BEGIN=snmp4jCfgReset
            setVolatile(true);
            //--AgentGen END
        }

        public void commit(SubRequest<?> request) {
            //--AgentGen BEGIN=snmp4jCfgReset::commit
            Integer32 newValue = (Integer32) request.getVariableBinding().getVariable();
            if (newValue.getValue() == Snmp4jCfgResetEnum.factoryReset) {
                setValue(new Integer32(Snmp4jCfgResetEnum.resetting));
                Snmp4jConfigMib.this.agentConfigManager.configure();
                Snmp4jConfigMib.this.agentConfigManager.saveState();
            }
            //--AgentGen END
            super.commit(request);
            if (newValue.getValue() == Snmp4jCfgResetEnum.factoryReset) {
                setValue(new Integer32(Snmp4jCfgResetEnum.done));
            }
        }

        public void cleanup(SubRequest<?> request) {
            //--AgentGen BEGIN=snmp4jCfgReset::cleanup
            //--AgentGen END
            super.cleanup(request);
        }

        public int isValueOK(SubRequest<?> request) {
            Variable newValue = request.getVariableBinding().getVariable();
            //--AgentGen BEGIN=snmp4jCfgReset::isValueOK
            switch (((Integer32) newValue).getValue()) {
                case Snmp4jCfgResetEnum.idle:
                case Snmp4jCfgResetEnum.factoryReset:
                    if (getValue().toInt() == Snmp4jCfgResetEnum.resetting) {
                        return PDU.inconsistentValue;
                    }
                    break;
                default:
                    return PDU.wrongValue;
            }
            //--AgentGen END
            return super.isValueOK(request);
        }
    }

    // Value Validators

    /**
     * The {@code Snmp4jCfgStoragePathValidator} implements the value validation for {@code Snmp4jCfgStoragePath}.
     */
    static class Snmp4jCfgStoragePathValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            OctetString os = (OctetString) newValue;
            if (!(((os.length() >= 0) && (os.length() <= 255)))) {
                validationEvent.setValidationStatus(SnmpConstants.SNMP_ERROR_WRONG_LENGTH);
                return;
            }
            //--AgentGen BEGIN=snmp4jCfgStoragePath::validate
            //--AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageFormatValidator} implements the value validation for {@code Snmp4jCfgStorageFormat}.
     */
    static class Snmp4jCfgStorageFormatValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            //--AgentGen BEGIN=snmp4jCfgStorageFormat::validate
            if (((Integer32) newValue).getValue() != Snmp4jCfgStorageFormatEnum.binary) {
                validationEvent.setValidationStatus(PDU.wrongValue);
            }
            //--AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageOperationValidator} implements the value validation for {@code
     * Snmp4jCfgStorageOperation}.
     */
    static class Snmp4jCfgStorageOperationValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            //--AgentGen BEGIN=snmp4jCfgStorageOperation::validate
            switch (newValue.toInt()) {
                case Snmp4jCfgStorageOperationEnum.restore:
                case Snmp4jCfgStorageOperationEnum.store:
                    break;
                default:
                    validationEvent.setValidationStatus(PDU.wrongValue);
            }
            //--AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageStorageTypeValidator} implements the value validation for
     * {@code Snmp4jCfgStorageStorageType}.
     */
    static class Snmp4jCfgStorageStorageTypeValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            // --AgentGen BEGIN=snmp4jCfgStorageStorageType::validate
            // --AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageStatusValidator} implements the value validation for {@code
     * Snmp4jCfgStorageStatus}.
     */
    static class Snmp4jCfgStorageStatusValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            // --AgentGen BEGIN=snmp4jCfgStorageStatus::validate
            // --AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageSeqSubtreeValidator} implements the value validation for {@code
     * Snmp4jCfgStorageSeqSubtree}.
     */
    static class Snmp4jCfgStorageSeqSubtreeValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            // --AgentGen BEGIN=snmp4jCfgStorageSeqSubtree::validate
            // --AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageSeqStorageTypeValidator} implements the value validation for
     * {@code Snmp4jCfgStorageSeqStorageType}.
     */
    static class Snmp4jCfgStorageSeqStorageTypeValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            // --AgentGen BEGIN=snmp4jCfgStorageSeqStorageType::validate
            // --AgentGen END
        }
    }

    /**
     * The {@code Snmp4jCfgStorageSeqRowStatusValidator} implements the value validation for
     * {@code Snmp4jCfgStorageSeqRowStatus}.
     */
    static class Snmp4jCfgStorageSeqRowStatusValidator implements MOValueValidationListener {

        public void validate(MOValueValidationEvent validationEvent) {
            Variable newValue = validationEvent.getNewValue();
            // --AgentGen BEGIN=snmp4jCfgStorageSeqRowStatus::validate
            // --AgentGen END
        }
    }

    // Enumerations
    public static final class Snmp4jCfgSecSrcAddrValidationEnum {
        public static final int enabled = 1;
        public static final int disabled = 2;
        public static final int notAvailable = 3;
    }

    public static final class Snmp4jCfgResetEnum {
        public static final int idle = 1;
        public static final int factoryReset = 2;
        public static final int resetting = 3;
        public static final int resetFailed = 4;
        public static final int done = 5;
    }

    public static final class Snmp4jCfgStorageFormatEnum {
        /* -- Default format */
        public static final int binary = 1;
        public static final int xml = 2;
    }

    public static final class Snmp4jCfgStorageRestoreModeEnum {
        public static final int replaceAndCreate = 1;
        public static final int updateAndCreate = 2;
        public static final int updateOnly = 3;
        public static final int createOnly = 4;
    }

    public static final class Snmp4jCfgStorageOperationEnum {
        /* -- no action */
        public static final int idle = 1;
        /* -- (re)store operation in progress */
        public static final int inProgress = 2;
        /* -- store current configuration */
        public static final int store = 3;
        /* -- restore configuration */
        public static final int restore = 4;
    }

    // Rows and Factories
    class Snmp4jCfgStorageEntryRowFactory
            implements MOTableRowFactory<Snmp4jCfgStorageEntryRow> {
        public Snmp4jCfgStorageEntryRowFactory() {
        }

        public Snmp4jCfgStorageEntryRow createRow(OID index, Variable[] values)
                throws UnsupportedOperationException {
            Snmp4jCfgStorageEntryRow row = new Snmp4jCfgStorageEntryRow(index, values);
            //--AgentGen BEGIN=snmp4jCfgStorageEntry::createRow
            ((Integer32) values[idxSnmp4jCfgStorageOperation]).
                    setValue(Snmp4jCfgStorageOperationEnum.idle);
            //--AgentGen END
            return row;
        }

        public void freeRow(Snmp4jCfgStorageEntryRow row) {
            //--AgentGen BEGIN=snmp4jCfgStorageEntry::freeRow
            //--AgentGen END
        }
    }

    public class Snmp4jCfgStorageEntryRow extends DefaultMOMutableRow2PC {

        public Snmp4jCfgStorageEntryRow(OID index, Variable[] values) {
            super(index, values);
        }

        public OctetString getSnmp4jCfgStoragePath() {
            return (OctetString) getValue(idxSnmp4jCfgStoragePath);
        }

        public void setSnmp4jCfgStoragePath(OctetString newValue) {
            setValue(idxSnmp4jCfgStoragePath, newValue);
        }

        public OctetString getSnmp4jCfgStorageID() {
            return (OctetString) getValue(idxSnmp4jCfgStorageID);
        }

        public void setSnmp4jCfgStorageID(OctetString newValue) {
            setValue(idxSnmp4jCfgStorageID, newValue);
        }

        public TimeTicks getSnmp4jCfgStorageLastStore() {
            return (TimeTicks) getValue(idxSnmp4jCfgStorageLastStore);
        }

        public void setSnmp4jCfgStorageLastStore(TimeTicks newValue) {
            setValue(idxSnmp4jCfgStorageLastStore, newValue);
        }

        public TimeTicks getSnmp4jCfgStorageLastRestore() {
            return (TimeTicks) getValue(idxSnmp4jCfgStorageLastRestore);
        }

        public void setSnmp4jCfgStorageLastRestore(TimeTicks newValue) {
            setValue(idxSnmp4jCfgStorageLastRestore, newValue);
        }

        public Integer32 getSnmp4jCfgStorageRestoreMode() {
            return (Integer32) getValue(idxSnmp4jCfgStorageRestoreMode);
        }

        public void setSnmp4jCfgStorageRestoreMode(Integer32 newValue) {
            setValue(idxSnmp4jCfgStorageRestoreMode, newValue);
        }

        public Integer32 getSnmp4jCfgStorageOperation() {
            return (Integer32) getValue(idxSnmp4jCfgStorageOperation);
        }

        public void setSnmp4jCfgStorageOperation(Integer32 newValue) {
            setValue(idxSnmp4jCfgStorageOperation, newValue);
        }

        public Integer32 getSnmp4jCfgStorageStorageType() {
            return (Integer32) getValue(idxSnmp4jCfgStorageStorageType);
        }

        public void setSnmp4jCfgStorageStorageType(Integer32 newValue) {
            setValue(idxSnmp4jCfgStorageStorageType, newValue);
        }

        public Integer32 getSnmp4jCfgStorageStatus() {
            return (Integer32) getValue(idxSnmp4jCfgStorageStatus);
        }

        public void setSnmp4jCfgStorageStatus(Integer32 newValue) {
            setValue(idxSnmp4jCfgStorageStatus, newValue);
        }

        //--AgentGen BEGIN=snmp4jCfgStorageEntry::RowFactory

        public void prepareRow(SubRequest<?> subRequest, MOTableRow changeSet) {
            if (PRIMARY_INDEX.equals(changeSet.getIndex())) {
                if (snmp4jCfgStorageEntryModel.getRow(PRIMARY_INDEX) == null) {
                    subRequest.getRequest().setErrorStatus(PDU.noCreation);
                }
            }
        }

        public void commitRow(SubRequest<?> subRequest, MOTableRow changeSet) {
            Integer32 operation = getSnmp4jCfgStorageOperation();
            OctetString providerID = getSnmp4jCfgStorageID();
            MOPersistenceProvider provider = getPersistenceProvider(providerID.toString());
            if (provider == null) {
                subRequest.getRequest().setErrorStatus(PDU.commitFailed);
            } else {
                Operation op =
                        new Operation(this, provider,
                                getSnmp4jCfgStorageRestoreMode().getValue(),
                                operation.getValue());
                setValue(idxSnmp4jCfgStorageOperation,
                        new Integer32(Snmp4jCfgStorageOperationEnum.inProgress));
                op.start();
            }
        }

        //--AgentGen END
    }

    public synchronized void freeRow(Snmp4jCfgStorageEntryRow row) {
        // --AgentGen BEGIN=snmp4jCfgStorageEntry::freeRow
        // --AgentGen END
    }

    // --AgentGen BEGIN=snmp4jCfgStorageEntry::RowFactory
    // --AgentGen END


    public class Snmp4jCfgStorageSeqEntryRow extends DefaultMOMutableRow2PC {

        // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::RowMembers
        // --AgentGen END

        public Snmp4jCfgStorageSeqEntryRow(OID index, Variable[] values) {
            super(index, values);
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::RowConstructor
            // --AgentGen END
        }

        public OID getSnmp4jCfgStorageSeqSubtree() {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::getSnmp4jCfgStorageSeqSubtree
            // --AgentGen END
            return (OID) super.getValue(idxSnmp4jCfgStorageSeqSubtree);
        }

        public void setSnmp4jCfgStorageSeqSubtree(OID newColValue) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::setSnmp4jCfgStorageSeqSubtree
            // --AgentGen END
            super.setValue(idxSnmp4jCfgStorageSeqSubtree, newColValue);
        }

        public Integer32 getSnmp4jCfgStorageSeqStorageType() {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::getSnmp4jCfgStorageSeqStorageType
            // --AgentGen END
            return (Integer32) super.getValue(idxSnmp4jCfgStorageSeqStorageType);
        }

        public void setSnmp4jCfgStorageSeqStorageType(Integer32 newColValue) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::setSnmp4jCfgStorageSeqStorageType
            // --AgentGen END
            super.setValue(idxSnmp4jCfgStorageSeqStorageType, newColValue);
        }

        public Integer32 getSnmp4jCfgStorageSeqRowStatus() {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::getSnmp4jCfgStorageSeqRowStatus
            // --AgentGen END
            return (Integer32) super.getValue(idxSnmp4jCfgStorageSeqRowStatus);
        }

        public void setSnmp4jCfgStorageSeqRowStatus(Integer32 newColValue) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::setSnmp4jCfgStorageSeqRowStatus
            // --AgentGen END
            super.setValue(idxSnmp4jCfgStorageSeqRowStatus, newColValue);
        }

        public Variable getValue(int column) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::RowGetValue
            // --AgentGen END
            switch (column) {
                case idxSnmp4jCfgStorageSeqSubtree:
                    return getSnmp4jCfgStorageSeqSubtree();
                case idxSnmp4jCfgStorageSeqStorageType:
                    return getSnmp4jCfgStorageSeqStorageType();
                case idxSnmp4jCfgStorageSeqRowStatus:
                    return getSnmp4jCfgStorageSeqRowStatus();
                default:
                    return super.getValue(column);
            }
        }

        public void setValue(int column, Variable value) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::RowSetValue
            // --AgentGen END
            switch (column) {
                case idxSnmp4jCfgStorageSeqSubtree:
                    setSnmp4jCfgStorageSeqSubtree((OID) value);
                    break;
                case idxSnmp4jCfgStorageSeqStorageType:
                    setSnmp4jCfgStorageSeqStorageType((Integer32) value);
                    break;
                case idxSnmp4jCfgStorageSeqRowStatus:
                    setSnmp4jCfgStorageSeqRowStatus((Integer32) value);
                    break;
                default:
                    super.setValue(column, value);
            }
        }

        // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::Row
        // --AgentGen END
    }

    public class Snmp4jCfgStorageSeqEntryRowFactory
            implements MOTableRowFactory<Snmp4jCfgStorageSeqEntryRow> {
        public synchronized Snmp4jCfgStorageSeqEntryRow createRow(OID index, Variable[] values)
                throws UnsupportedOperationException {
            Snmp4jCfgStorageSeqEntryRow row = new Snmp4jCfgStorageSeqEntryRow(index, values);
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::createRow
            // --AgentGen END
            return row;
        }

        public synchronized void freeRow(Snmp4jCfgStorageSeqEntryRow row) {
            // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::freeRow
            // --AgentGen END
        }

        // --AgentGen BEGIN=snmp4jCfgStorageSeqEntry::RowFactory
        // --AgentGen END

    }

//--AgentGen BEGIN=_METHODS

    public void setSnmpCommunityMIB(SnmpCommunityMIB snmpCommunityMIB) {
        this.snmpCommunityMIB = snmpCommunityMIB;
    }

    public void setPrimaryProvider(MOPersistenceProvider persistenceProvider) {
        this.primaryPersistence = persistenceProvider;

        Snmp4jCfgStorageEntryRow primary = snmp4jCfgStorageEntryModel.getRow(PRIMARY_INDEX);
        if (primary == null) {
            Variable[] vbs = snmp4jCfgStorageEntry.getDefaultValues();
            vbs[idxSnmp4jCfgStorageStatus] = new Integer32(RowStatus.active);
            primary = snmp4jCfgStorageEntry.createRow(PRIMARY_INDEX, vbs);
            primary.setSnmp4jCfgStorageID(new OctetString(persistenceProvider.getPersistenceProviderID()));
            primary.setSnmp4jCfgStorageStorageType(
                    new Integer32(StorageType.permanent));
            primary.setSnmp4jCfgStorageOperation(
                    new Integer32(Snmp4jCfgStorageOperationEnum.idle));
            snmp4jCfgStorageEntry.addRow(primary);
        }
        primary.setSnmp4jCfgStoragePath(
                new OctetString(primaryPersistence.getDefaultURI()));
        addPersistenceProvider(persistenceProvider);
    }

    public void addPersistenceProvider(MOPersistenceProvider provider) {
        persistenceProvider.put(provider.getPersistenceProviderID(), provider);
    }

    public MOPersistenceProvider getPersistenceProvider(String id) {
        return persistenceProvider.get(id);
    }

    public SnmpCommunityMIB getCoexistenceInfoProvider() {
        return this.snmpCommunityMIB;
    }

//--AgentGen END

//--AgentGen BEGIN=_CLASSES

    private class Operation extends Thread {

        private Snmp4jCfgStorageEntryRow row;
        private int operation;
        private int restoreType;
        private MOPersistenceProvider provider;

        public Operation(Snmp4jCfgStorageEntryRow row,
                         MOPersistenceProvider provider,
                         int restoreType,
                         int operation) {
            this.operation = operation;
            this.provider = provider;
            this.restoreType = restoreType;
            this.row = row;
        }

        public void run() {
            switch (operation) {
                case Snmp4jCfgStorageOperationEnum.store: {
                    String path = row.getValue(idxSnmp4jCfgStoragePath).toString();
                    try {
                        provider.store(path, Snmp4jConfigMib.this);
                        row.setValue(idxSnmp4jCfgStorageLastStore, sysUpTime.get());
                        row.setValue(idxSnmp4jCfgStorageOperation,
                                new Integer32(Snmp4jCfgStorageOperationEnum.idle));
                    } catch (Exception iox) {
                        logger.error("Failed to store config to '" + path + "': " + iox.getMessage(), iox);
                        row.setValue(idxSnmp4jCfgStorageOperation,
                                new Integer32(Snmp4jCfgStorageOperationEnum.idle));
                    }
                    break;
                }
                case Snmp4jCfgStorageOperationEnum.restore: {
                    String f = row.getValue(idxSnmp4jCfgStoragePath).toString();
                    try {
                        provider.restore(f, restoreType, Snmp4jConfigMib.this);
                        row.setValue(idxSnmp4jCfgStorageLastRestore, sysUpTime.get());
                        row.setValue(idxSnmp4jCfgStorageOperation,
                                new Integer32(Snmp4jCfgStorageOperationEnum.idle));
                    } catch (Exception iox) {
                        logger.error("Failed to restore config from '" + f + "': " +
                                iox.getMessage(), iox);
                        row.setValue(idxSnmp4jCfgStorageOperation,
                                new Integer32(Snmp4jCfgStorageOperationEnum.idle));
                    }
                    break;
                }
            }
        }
    }

//--AgentGen END
// --AgentGen BEGIN=_END
//--AgentGen END
}


