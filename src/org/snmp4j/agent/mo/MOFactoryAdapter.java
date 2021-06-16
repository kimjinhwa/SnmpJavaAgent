/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOFactoryAdapter.java  
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

import org.snmp4j.agent.MOAccess;
import org.snmp4j.agent.mo.snmp.SysUpTime;
import org.snmp4j.agent.mo.snmp.tc.TextualConvention;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;

/**
 * The {@link MOFactoryAdapter} class wraps a {@link MOFactory} and per default delegates all method calls to that
 * class. User of the adapter can then overwrite and adapt the behavior of the underlying factory for special needs
 * of a certain group of MIB objects, for example during creation of a MIB module.
 *
 * @author Frank Fock
 * @version 3.0.0
 */
public class MOFactoryAdapter implements MOFactory {

    private MOFactory delegateFactory;

    public MOFactoryAdapter(MOFactory delegateFactory) {
        this.delegateFactory = delegateFactory;
    }

    @Override
    public void addTextualConvention(TextualConvention<?> tc) {
        delegateFactory.addTextualConvention(tc);
    }

    @Override
    public void removeTextualConvention(TextualConvention<?> tc) {
        delegateFactory.removeTextualConvention(tc);
    }

    @Override
    public <V extends Variable> TextualConvention<V> getTextualConvention(String moduleName, String name) {
        return delegateFactory.getTextualConvention(moduleName, name);
    }

    @Override
    public MOAccess createAccess(int moAccess) {
        return delegateFactory.createAccess(moAccess);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public <R extends MOTableRow, M extends MOTableModel<R>> MOTable<R, MOColumn, M>
    createTable(OID oid, MOTableIndex indexDef, MOColumn[] columns) {
        return delegateFactory.createTable(oid, indexDef, columns);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public <R extends MOTableRow, M extends MOTableModel<R>> MOTable<R, MOColumn, M>
    createTable(OID oid, MOTableIndex indexDef, MOColumn[] columns, M model) {
        return delegateFactory.createTable(oid, indexDef, columns, model);
    }

    @Override
    public MOTableIndex createIndex(MOTableSubIndex[] subIndexes, boolean impliedLength) {
        return delegateFactory.createIndex(subIndexes, impliedLength);
    }

    @Override
    public MOTableIndex createIndex(MOTableSubIndex[] subIndexes, boolean impliedLength, MOTableIndexValidator validator) {
        return delegateFactory.createIndex(subIndexes, impliedLength, validator);
    }

    @Override
    public MOTableSubIndex createSubIndex(OID oid, int smiSyntax) {
        return delegateFactory.createSubIndex(oid, smiSyntax);
    }

    @Override
    public MOTableSubIndex createSubIndex(OID oid, int smiSyntax, int minLength, int maxLength) {
        return delegateFactory.createSubIndex(oid, smiSyntax, minLength, maxLength);
    }

    @Override
    public <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access) {
        return delegateFactory.createColumn(columnID, syntax, access);
    }

    @Override
    public <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access, String tcModuleName,
                                                         String textualConvention) {
        return delegateFactory.createColumn(columnID, syntax, access, tcModuleName, textualConvention);
    }

    @Override
    public <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access, V defaultValue,
                                                         boolean mutableInService) {
        return delegateFactory.createColumn(columnID, syntax, access, defaultValue, mutableInService);
    }

    @Override
    public <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access, V defaultValue,
                                                         boolean mutableInService, String tcModuleName, String textualConvention) {
        return delegateFactory.createColumn(columnID, syntax, access, defaultValue, mutableInService, tcModuleName, textualConvention);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public <R extends MOTableRow, M extends MOTableModel<? extends R>> M
    createTableModel(OID tableOID, MOTableIndex indexDef, MOColumn[] columns) {
        return delegateFactory.createTableModel(tableOID, indexDef, columns);
    }

    @Override
    public <V extends Variable> MOScalar<V> createScalar(OID id, MOAccess access, V value) {
        return delegateFactory.createScalar(id, access, value);
    }

    @Override
    public <V extends Variable> MOScalar<V> createScalar(OID id, MOAccess access, V value, String tcModuleName, String textualConvention) {
        return delegateFactory.createScalar(id, access, value, tcModuleName, textualConvention);
    }

    @Override
    @SuppressWarnings("rawtypes")
    public <BaseRow extends MOTableRow, DependentRow extends MOTableRow> MOTableRelation<BaseRow, DependentRow>
    createTableRelation(MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> baseTable,
                        MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> dependentTable) {
        return delegateFactory.createTableRelation(baseTable, dependentTable);
    }

    @Override
    public SysUpTime getSysUpTime(OctetString context) {
        return delegateFactory.getSysUpTime(context);
    }
}
