/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - VacmConfigurator.java  
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

import org.snmp4j.security.USM;
import org.snmp4j.smi.OctetString;

/**
 * The {@link VacmConfigurator} defines an easy to use interface for {@link MutableVACM} configuration.
 * Implementations of this class can provide role/group based VACM security configurations that hide all the
 * {@link VACM} details. Each implementation of this interface defines a role and their security settings.
 *
 * @author Frank Fock
 * @since 3.0
 */
public interface VacmConfigurator {

    enum VacmConfigResult {
        userAddedToRole, userAndRoleAdded, userRemovedFromRole, roleRemoved,
        userExists, groupExists, viewExists, roleNotSupported,
        roleDoesNotExist, userDoesNotExist, unknownError
    }

    /**
     * Add a new user to a group. If the referenced group does not exist, it will be created. If the role identified
     * by the group is not supported by this configurator, an error is returned.
     * @param vacm
     *    the {@link MutableVACM} to modify
     * @param securityName
     *    the user name of the new user.
     * @param role
     *    the group (VACM)/role name associated with the user. Only supported groups must ber provided.
     *    See {@link #getSupportedRoles()}.
     * @return
     *    the operation result.
     */
    VacmConfigResult addUser(MutableVACM vacm, OctetString securityName, String role);

    /**
     * Remove a new user from the specified group. If the referenced group does not exist, nothing will be changed and
     * {@link VacmConfigResult#userRemovedFromRole} will be returned.
     * If the role identified
     * by the group is not supported by this configurator, an error is returned.
     * @param vacm
     *    the {@link MutableVACM} to modify
     * @param securityName
     *    the user name of the new user.
     * @param role
     *    the group (VACM)/role name associated with the user. Only supported groups must be provided.
     *    See {@link #getSupportedRoles()}.
     * @return
     *    the operation result.
     */
    VacmConfigResult removeUser(MutableVACM vacm, OctetString securityName, String role);

    /**
     * Remover all users from the specified security group and then remove the group itself. This operation will
     * only affect the {@link VACM} provided, but not the {@link USM}.
     * @param vacm
     *    the {@link MutableVACM} to modify
     * @param role
     *    the group (VACM)/role to be removed from the above {@code vacm}.
     * @return
     *    the operation result.
     */
    VacmConfigResult removeRole(MutableVACM vacm, String role);

    /**
     * Returns the list of roles supported by this configurator.
     * @return
     *    a non-empty array of roles/groups supported by this configurator.
     */
    String[] getSupportedRoles();


}
