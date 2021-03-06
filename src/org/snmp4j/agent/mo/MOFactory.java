/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - MOFactory.java  
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

import org.snmp4j.agent.mo.snmp.SNMPv2MIB;
import org.snmp4j.agent.mo.snmp.SysUpTime;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.agent.MOAccess;
import org.snmp4j.agent.mo.snmp.tc.TextualConvention;
// for JavaDoc
import org.snmp4j.smi.SMIConstants;

/**
 * The {@code MOFactory} interface provides factory methods for creating
 * all types of managed objects known by SNMP4J-Agent. By using this factory
 * instead of creating the managed objects and related objects directly,
 * one can easily install a sort of aspect oriented layer into the managed
 * object instrumentation.
 *
 * @author Frank Fock
 * @version 3.0.0
 */
public interface MOFactory {

    /**
     * Adds a textual convention to this factory which can then be used by the
     * factory to create appropriate value constraints for columnar and scalar
     * managed objects.
     *
     * @param tc
     *         a TextualConvention instance.
     */
    void addTextualConvention(TextualConvention<?> tc);

    /**
     * Removes the supplied textual convention from the supported TCs by this
     * ManagedObject factory.
     *
     * @param tc
     *         a TextualConvention instance.
     */
    void removeTextualConvention(TextualConvention<?> tc);

    /**
     * Gets the textual convention described by the TC's name and the MIB module
     * name of the MIB module specifying the TC.
     *
     * @param moduleName
     *         the name of the MIB module that defines the TC.
     * @param name
     *         the object name of the TC.
     * @param <V>
     *         the {@link Variable} type that is the base type of the returned textual convention.
     *
     * @return the {@code TextualConvention} that matches the given values, or
     * {@code null} if such a TC is not registered with this factory.
     */
    <V extends Variable> TextualConvention<V> getTextualConvention(String moduleName, String name);

    /**
     * Creates an MOAccess instance from an access specification constant that is
     * the result of a bitwise OR of any of the constants defined by
     * {@link MOAccess}.
     *
     * @param moAccess
     *         any bitwise OR combined constant from {@link MOAccess}.
     *
     * @return a MOAccess instance.
     */
    default MOAccess createAccess(int moAccess) {
        return MOAccessImpl.getInstance(moAccess);
    }

    /**
     * Creates a MOTable instance for the supplied OID, index definition, and
     * columns with the {@link DefaultMOMutableTableModel} as table model.
     *
     * @param oid
     *         the OID of the table entry (thus table OID + ".1").
     * @param indexDef
     *         the index definition of the table.
     * @param columns
     *         the columns for the new table as an array of {@code MOColumn}
     *         instances.
     * @param <R>
     *         the {@link MOTableRow} type of the table to return.
     * @param <M>
     *         the {@link MOTableModel} type of the table to return.
     *
     * @return a MOTable instance.
     */
    @SuppressWarnings(value={"rawtypes","unchecked"})
    default <R extends MOTableRow, M extends MOTableModel<R>> MOTable<R, MOColumn, M>
    createTable(OID oid, MOTableIndex indexDef, MOColumn[] columns) {
        return createTable(oid, indexDef, columns, (M) createTableModel(oid, indexDef, columns));
    }


    /**
     * Creates a MOTable instance for the supplied OID, index definition,
     * columns, and table model.
     *
     * @param oid
     *         the OID of the table entry (thus table OID + ".1").
     * @param indexDef
     *         the index definition of the table.
     * @param columns
     *         the columns for the new table as an array of {@code MOColumn}
     *         instances.
     * @param model
     *         the table model to use for the table.
     * @param <R>
     *         the {@link MOTableRow} type of the table to return.
     * @param <M>
     *         the {@link MOTableModel} type of the table to return.
     *
     * @return a MOTable instance.
     */
    @SuppressWarnings(value={"rawtypes"})
    default <R extends MOTableRow, M extends MOTableModel<R>> MOTable<R, MOColumn, M>
    createTable(OID oid, MOTableIndex indexDef, MOColumn[] columns, M model) {
        return new DefaultMOTable<R, MOColumn, M>(oid, indexDef, columns, model);
    }

    /**
     * Creates an index definition from the supplied sub-index definitions without
     * index validation.
     *
     * @param subIndexes
     *         an array of {@code MOTableSubIndex} instances defining the sub-
     *         index values of this index.
     * @param impliedLength
     *         indicates whether the last variable length sub-index value has an
     *         implied length or not (default is false).
     *
     * @return MOTableIndex
     * a {@code MOTableIndex} instance.
     */
    default MOTableIndex createIndex(MOTableSubIndex[] subIndexes, boolean impliedLength) {
        return new MOTableIndex(subIndexes, impliedLength);
    }


    /**
     * Creates an index definition from the supplied sub-index definitions with
     * index validation according to the supplied validator.
     *
     * @param subIndexes
     *         an array of {@code MOTableSubIndex} instances defining the sub-
     *         index values of this index.
     * @param impliedLength
     *         indicates whether the last variable length sub-index value has an
     *         implied length or not (default is false).
     * @param validator
     *         an index validator to check index values.
     *
     * @return MOTableIndex
     * a {@code MOTableIndex} instance.
     */
    default MOTableIndex createIndex(MOTableSubIndex[] subIndexes, boolean impliedLength,
                                     MOTableIndexValidator validator) {
        return new MOTableIndex(subIndexes, impliedLength, validator);
    }

    /**
     * Creates a sub-index definition.
     *
     * @param oid
     *         the object identifier of the OBJECT-TYPE that defines this sub-index
     *         or {@code null} if that information is not available. An non
     *         {@code null} is required for AgentX shared tables.
     * @param smiSyntax
     *         the SMI syntax as defined by {@link SMIConstants}.
     *
     * @return a {@code MOTableSubIndex} instance.
     * @since 1.1
     */
    default MOTableSubIndex createSubIndex(OID oid, int smiSyntax) {
        return new MOTableSubIndex(oid, smiSyntax);
    }

    /**
     * Creates a sub-index definition.
     *
     * @param oid
     *         the object identifier of the OBJECT-TYPE that defines this sub-index
     *         or {@code null} if that information is not available. An non
     *         {@code null} is required for AgentX shared tables.
     * @param smiSyntax
     *         the SMI syntax as defined by {@link SMIConstants}.
     * @param minLength
     *         the minimum length in sub-identifiers (without length sub-id) of the
     *         sub-index.
     * @param maxLength
     *         the maximum length in sub-identifiers (without length sub-id) of the
     *         sub-index.
     *
     * @return a {@code MOTableSubIndex} instance.
     * @since 1.1
     */
    default MOTableSubIndex createSubIndex(OID oid, int smiSyntax, int minLength, int maxLength) {
        return new MOTableSubIndex(oid, smiSyntax, minLength, maxLength);
    }

    /**
     * Creates a columnar object by supplying column ID, syntax, and maximum
     * access. Use this method for columns not based on a textual convention.
     *
     * @param columnID
     *         the column ID of the column. The column ID is the last sub-identifier
     *         of a column definition. It is NOT the index of the column.
     * @param syntax
     *         the SMI syntax of the column as defined by {@link SMIConstants}.
     * @param access
     *         the maximum access supported by this column.
     * @param <V>
     *         the {@link Variable} type of the column to return.
     *
     * @return a {@code MOColumn} instance.
     */
    default <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access) {
        return new MOMutableColumn<V>(columnID, syntax, access);
    }

    /**
     * Creates a columnar object by supplying column ID, syntax, and maximum
     * access. Use this method for columns based on the textual convention.
     *
     * @param columnID
     *         the column ID of the column. The column ID is the last sub-identifier
     *         of a column definition. It is NOT the index of the column.
     * @param syntax
     *         the (effective) SMI syntax of the column as defined by
     *         {@link SMIConstants}.
     * @param access
     *         the maximum access supported by this column.
     * @param tcModuleName
     *         the MIB module name that defines the textual conventions.
     * @param textualConvention
     *         the object name of the textual convention on which this column is based.
     * @param <V>
     *         the {@link Variable} type of the column to return.
     *
     * @return a {@code MOColumn} instance.
     */
    default <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access,
                                  String tcModuleName, String textualConvention) {
        TextualConvention<V> tc = getTextualConvention(tcModuleName, textualConvention);
        if (tc != null) {
            return tc.createColumn(columnID, syntax, access, (V) null, true);
        }
        return createColumn(columnID, syntax, access);
    }

    /**
     * Creates a columnar object by supplying column ID, syntax, and maximum
     * access. Use this method for columns based on the textual convention.
     *
     * @param columnID
     *         the column ID of the column. The column ID is the last sub-identifier
     *         of a column definition. It is NOT the index of the column.
     * @param syntax
     *         the (effective) SMI syntax of the column as defined by
     *         {@link SMIConstants}.
     * @param access
     *         the maximum access supported by this column.
     * @param defaultValue
     *         the default value defined by the DEFVAL clause for this column.
     * @param mutableInService
     *         if {@code true} this object may be changed while it is active
     *         (inService), otherwise such an attempt will be rejected with a
     *         inconsistentValue error.
     * @param <V>
     *         the {@link Variable} type of the column to return.
     *
     * @return a {@code MOColumn} instance.
     */
    default <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access,
                                                          V defaultValue, boolean mutableInService) {
        return new MOMutableColumn<V>(columnID, syntax, access, defaultValue, mutableInService);
    }


    /**
     * Creates a columnar object by supplying column ID, syntax, and maximum
     * access. Use this method for columns based on the textual convention.
     *
     * @param columnID
     *         the column ID of the column. The column ID is the last sub-identifier
     *         of a column definition. It is NOT the index of the column.
     * @param syntax
     *         the (effective) SMI syntax of the column as defined by
     *         {@link SMIConstants}.
     * @param access
     *         the maximum access supported by this column.
     * @param defaultValue
     *         the default value defined by the DEFVAL clause for this column.
     * @param mutableInService
     *         if {@code true} this object may be changed while it is active
     *         (inService), otherwise such an attempt will be rejected with a
     *         inconsistentValue error.
     * @param tcModuleName
     *         the MIB module name that defines the textual conventions.
     * @param textualConvention
     *         the object name of the textual convention on which this column is based.
     * @param <V>
     *         the {@link Variable} type of the column to return.
     *
     * @return a {@code MOColumn} instance.
     */
    default <V extends Variable> MOColumn<V> createColumn(int columnID, int syntax, MOAccess access,
                                                          V defaultValue, boolean mutableInService,
                                  String tcModuleName, String textualConvention) {
        TextualConvention<V> tc =
                getTextualConvention(tcModuleName, textualConvention);
        if (tc != null) {
            return tc.createColumn(columnID, syntax, access,
                    defaultValue, mutableInService);
        }
        return createColumn(columnID, syntax, access,
                defaultValue, mutableInService);
    }

    /**
     * Creates a table model (by default a {@link DefaultMOMutableTableModel}).
     *
     * @param tableOID
     *         the table's OID for which this model is created.
     * @param indexDef
     *         the index definition for the table.
     * @param columns
     *         the columns defined for the table.
     * @param <R>
     *         the {@link MOTableRow} type of the table model to return.
     * @param <M>
     *         the {@link MOTableModel} type of the table model to return.
     *
     * @return a {@code MOTableModel} instance.
     * @since 1.1
     */
    @SuppressWarnings(value={"rawtypes","unchecked"})
    default <R extends MOTableRow, M extends MOTableModel<? extends R>> M createTableModel(
            OID tableOID, MOTableIndex indexDef, MOColumn[] columns) {
        return (M) new DefaultMOMutableTableModel<R>();
    }

    /**
     * Creates a scalar object from a OID, maximum access, and value.
     *
     * @param id
     *         the OID of the scalar (including the .0 suffix).
     * @param access
     *         the maximum access supported by this scalar.
     * @param value
     *         the (initial) value of the scalar.
     * @param <V>
     *         the {@link Variable} type of the scalar to return.
     *
     * @return a {@code MOScalar} instance.
     */
    default <V extends Variable> MOScalar<V> createScalar(OID id, MOAccess access, V value) {
        return new MOScalar<V>(id, access, value);
    }

    /**
     * Creates a scalar object from a OID, maximum access, and value.
     *
     * @param id
     *         the OID of the scalar (including the .0 suffix).
     * @param access
     *         the maximum access supported by this scalar.
     * @param value
     *         the (initial) value of the scalar.
     * @param tcModuleName
     *         the MIB module name that defines the textual conventions.
     * @param textualConvention
     *         the object name of the textual convention on which this scalar is based.
     * @param <V>
     *         the {@link Variable} type of the scalar to return.
     *
     * @return a {@code MOScalar} instance.
     */
    default <V extends Variable> MOScalar<V> createScalar(OID id, MOAccess access, V value,
                                                          String tcModuleName, String textualConvention) {
        TextualConvention<V> tc =
                getTextualConvention(tcModuleName, textualConvention);
        if (tc != null) {
            return tc.createScalar(id, access, value);
        }
        return createScalar(id, access, value);
    }


    /**
     * Creates a relation between two tables. Related tables share one or more
     * sub-indexes beginning with the first sub-index.
     *
     * @param baseTable
     *         the base table.
     * @param dependentTable
     *         the dependent or augmenting table.
     * @param <BaseRow>
     *         the base row type of the table relation.
     * @param <DependentRow>
     *         the dependent row type of the table relation.
     *
     * @return a {@code MOTableRelation} instance relating the supplied tables.
     */
    @SuppressWarnings(value={"rawtypes"})
    default <BaseRow extends MOTableRow, DependentRow extends MOTableRow>
    MOTableRelation<BaseRow, DependentRow> createTableRelation(
            MOTable<BaseRow, ? extends MOColumn, ? extends MOTableModel<BaseRow>> baseTable,
            MOTable<DependentRow, ? extends MOColumn, ? extends MOTableModel<DependentRow>> dependentTable) {
        return new MOTableRelation<>(baseTable, dependentTable);
    }


    /**
     * Gets a reference to the systems up-time object for the specified context.
     *
     * @param context
     *         the SNMPv3 context for which the up-time object should be returned. If the context is null, the up-time
     *         of the default context is returned.
     *
     * @return a reference to a {@link org.snmp4j.agent.mo.snmp.SysUpTime} implementation.
     * @since 2.3.0
     */
    default SysUpTime getSysUpTime(OctetString context) {
        return SNMPv2MIB.getSysUpTime(context);
    }
}
