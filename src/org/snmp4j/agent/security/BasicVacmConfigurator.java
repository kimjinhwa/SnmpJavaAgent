/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - BasicVacmConfigurator.java  
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

package org.snmp4j.agent.security;

import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.util.Set;

/**
 * The {@code BasicVacmConfigurator} implements the {@link VacmConfigurator} that uses three unrestricted views
 * for all access types to support two roles {@code admin} and {@code monitor}. The {@code admin} role has unrestricted
 * access to the agent, whereas {@code monitor} has no write access, but unrestricted read and notification access.
 *
 * @since 3.0
 * @author Frank Fock
 */
public class BasicVacmConfigurator  implements VacmConfigurator {

    public enum Roles {
        admin("admin"),
        monitor("monitor");

        private String roleName;

        Roles(String roleName) {
            this.roleName = roleName;
        }

        public String getRoleName() {
            return roleName;
        }
    }

    protected OctetString rootViewName = new OctetString("rootView");

    protected OID rootOID = new OID(new int[] { 1 });
    protected SecurityModel securityModel;
    protected SecurityLevel securityLevel;
    protected OctetString contextPrefix = new OctetString();
    protected int contextMatch = MutableVACM.VACM_MATCH_EXACT;


    @Override
    public VacmConfigResult addUser(MutableVACM vacm, OctetString securityName, String role) {
        OctetString groupName = new OctetString(role);
        if (vacm.hasSecurityToGroupMapping(securityModel.getID(), securityName)) {
            return VacmConfigResult.userExists;
        }
        vacm.addGroup(securityModel.getID(), securityName, groupName, StorageType.nonVolatile);
        VacmConfigResult vacmConfigResult = VacmConfigResult.userAddedToRole;
        if (vacm.viewTreeFamilyEntryCount(rootViewName) == 0) {
            vacm.addViewTreeFamily(rootViewName, rootOID, new OctetString(), VacmMIB.VACM_VIEW_INCLUDED,
                    StorageType.nonVolatile);
            vacmConfigResult = VacmConfigResult.userAndRoleAdded;
        }
        if (vacm.accessEntryCount(groupName) == 0) {
            vacm.addAccess(groupName, contextPrefix, securityModel.getID(), securityLevel.getSnmpValue(),
                    contextMatch, rootViewName,
                    (Roles.admin.getRoleName().equals(role) ? rootViewName : null),
                    rootViewName, StorageType.nonVolatile);
            vacmConfigResult = VacmConfigResult.userAndRoleAdded;
        }
        return vacmConfigResult;
    }

    @Override
    public VacmConfigResult removeUser(MutableVACM vacm, OctetString securityName, String role) {
        if (vacm.hasSecurityToGroupMapping(securityModel.getID(), securityName)) {
            if (vacm.removeGroup(securityModel.getID(), securityName)) {
                return VacmConfigResult.userRemovedFromRole;
            }
        }
        return VacmConfigResult.userDoesNotExist;
    }

    @Override
    public VacmConfigResult removeRole(MutableVACM vacm, String role) {
        if (isRoleSupported(role)) {
            OctetString groupName = new OctetString(role);
            if (!vacm.removeAccess(groupName, contextPrefix, securityModel.getID(), securityLevel.getSnmpValue())) {
                return VacmConfigResult.roleDoesNotExist;
            }
            if (vacm.removeViewTreeFamily(rootViewName, rootOID)) {
                return VacmConfigResult.roleRemoved;
            }
        }
        return VacmConfigResult.roleNotSupported;
    }

    @Override
    public String[] getSupportedRoles() {
        return new String[] { Roles.admin.getRoleName(), Roles.monitor.getRoleName() };
    }

    protected boolean isRoleSupported(String role) {
        for (String r : getSupportedRoles()) {
            if (r.equals(role)) {
                return true;
            }
        }
        return false;
    }
}
