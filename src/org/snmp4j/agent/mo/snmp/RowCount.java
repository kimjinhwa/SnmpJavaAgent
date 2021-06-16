/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - RowCount.java  
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

import org.snmp4j.agent.mo.MOTable;
import org.snmp4j.asn1.BER;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.smi.*;

import java.io.IOException;
import java.io.OutputStream;

/**
 * The {@code RowCount} class implements a {@link Variable} that counts the rows of a table and returns the number
 * of rows as value. This class is a dynamic Variable, which means it needs to be cloned when serialized.
 * When cloned, a {@link Gauge32} instance with the row count of the source table will be created.
 *
 * @author Frank Fock
 * @since 3.2.1
 */
public class RowCount implements Variable {

    private MOTable table;

    /**
     * Creates a {@link RowCount} which returns zero always.
     */
    public RowCount() {
        this(null);
    }

    /**
     * Creates a row counting {@code Gauge32} variable for the specified {@link MOTable}.
     * @param moTable
     *    a table instance whose rows should be counted by this variable.
     */
    public RowCount(MOTable moTable) {
        this.table = moTable;
    }

    /**
     * Gets the number of rows in the associated table as unsigned long value.
     * @return
     *    the number of rows in the associated table (greater or equal to zero). Zero is returned if a {@code null}
     *    table is associated.
     */
    public long getValue() {
        return (table == null || table.getModel() == null) ? 0 : table.getModel().getRowCount();
    }

    @Override
    public int compareTo(Variable o) {
        long diff = (getValue() - ((UnsignedInteger32) o).getValue());
        if (diff < 0) {
            return -1;
        } else if (diff > 0) {
            return 1;
        }
        return 0;
    }

    /**
     * Clones this variable. Cloning can be used by the SNMP4J API to better support concurrency by creating a clone for
     * internal processing. The content of this object is independent to the content of the clone. Thus, changes to the
     * clone will have no effect to this object.
     *
     * @return a new instance of this {@code Variable} with the same value.
     */
    @Override
    public Object clone() {
        return new Gauge32(getValue());
    }

    /**
     * Gets the ASN.1 syntax identifier value of this SNMP variable.
     *
     * @return an integer value &lt; 128 for regular SMI objects and a value &gt;= 128 for exception values like
     * noSuchObject, noSuchInstance, and endOfMibView.
     */
    @Override
    public int getSyntax() {
        return SMIConstants.SYNTAX_GAUGE32;
    }

    /**
     * Checks whether this variable represents an exception like noSuchObject, noSuchInstance, and endOfMibView.
     *
     * @return {@code true} if the syntax of this variable is an instance of {@code Null} and its syntax equals one of
     * the following:
     * <UL>
     * <LI>{@link SMIConstants#EXCEPTION_NO_SUCH_OBJECT}</LI>
     * <LI>{@link SMIConstants#EXCEPTION_NO_SUCH_INSTANCE}</LI>
     * <LI>{@link SMIConstants#EXCEPTION_END_OF_MIB_VIEW}</LI>
     * </UL>
     */
    @Override
    public boolean isException() {
        return false;
    }

    /**
     * Returns an integer representation of this variable if such a representation exists.
     *
     * @return an integer value (if the native representation of this variable would be a long, then the long value will
     * be casted to int).
     * @throws UnsupportedOperationException
     *         if an integer representation does not exists for this Variable.
     */
    @Override
    public int toInt() {
        return (int)getValue();
    }

    /**
     * Returns a long representation of this variable if such a representation exists.
     *
     * @return a long value.
     * @throws UnsupportedOperationException
     *         if a long representation does not exists for this Variable.
     */
    @Override
    public long toLong() {
        return getValue();
    }

    /**
     * Gets a textual description of this Variable.
     *
     * @return a textual description like 'Integer32' as used in the Structure of Management Information (SMI) modules.
     * '?' is returned if the syntax is unknown.
     */
    @Override
    public String getSyntaxString() {
        return new Gauge32().getSyntaxString();
    }

    /**
     * Converts the value of this {@code Variable} to a (sub-)index value.
     *
     * @param impliedLength
     *         specifies if the sub-index has an implied length. This parameter applies to variable length variables
     *         only (e.g. {@link OctetString} and {@link OID}). For other variables it has no effect.
     *
     * @return an OID that represents this value as an (sub-)index.
     * @throws UnsupportedOperationException
     *         if this variable cannot be used in an index.
     */
    @Override
    public OID toSubIndex(boolean impliedLength) {
        return new Gauge32(getValue()).toSubIndex(impliedLength);
    }

    /**
     * Sets the value of this {@code Variable} from the supplied (sub-)index.
     *
     * @param subIndex
     *         the sub-index OID.
     * @param impliedLength
     *         specifies if the sub-index has an implied length. This parameter applies to variable length variables
     *         only (e.g. {@link OctetString} and {@link OID}). For other variables it has no effect.
     *
     * @throws UnsupportedOperationException
     *         if this variable cannot be used in an index.
     */
    @Override
    public void fromSubIndex(OID subIndex, boolean impliedLength) {
        throw new UnsupportedOperationException();
    }

    /**
     * Indicates whether this variable is dynamic. If a variable is dynamic, precautions have to be taken when a
     * Variable is serialized using BER encoding, because between determining the length with {@link #getBERLength()}
     * for encoding enclosing SEQUENCES and the actual encoding of the Variable itself with {@link #encodeBER} changes
     * to the value need to be blocked by synchronization. In order to ensure proper synchronization if a {@code
     * Variable} is dynamic, modifications of the variables content need to synchronize on the {@code Variable}
     * instance. This can be achieved for the standard SMI Variable implementations for example by
     * <pre>
     *    public static modifyVariable(Integer32 variable, int value)
     *      synchronize(variable) {
     *        variable.setValue(value);
     *      }
     *    }
     * </pre>
     *
     * @return {@code true} because the variable might change its value between two calls to {@link #getBERLength()} and
     * {@link #encodeBER}.
     */
    @Override
    public boolean isDynamic() {
        return true;
    }

    /**
     * Returns the length of this {@code BERSerializable} object in bytes when encoded according to the Basic
     * Encoding Rules (BER).
     *
     * @return the BER encoded length of this variable.
     */
    @Override
    public int getBERLength() {
        return UnsignedInteger32.getBERLengthFromValue(getValue());
    }

    /**
     * Returns the length of the payload of this {@code BERSerializable} object in bytes when encoded according to
     * the Basic Encoding Rules (BER).
     *
     * @return the BER encoded length of this variable.
     */
    @Override
    public int getBERPayloadLength() {
        return getBERLength();
    }

    /**
     * Decodes a {@code Variable} from an {@code InputStream}.
     *
     * @param inputStream
     *         an {@code InputStream} containing a BER encoded byte stream.
     *
     * @throws IOException
     *         if the stream could not be decoded by using BER rules.
     */
    @Override
    public void decodeBER(BERInputStream inputStream) throws java.io.IOException {
        throw new UnsupportedOperationException("RowCount cannot be decoded from BER");
    }

    /**
     * Encodes a {@code Variable} to an {@code OutputStream}.
     *
     * @param outputStream
     *         an {@code OutputStream}.
     *
     * @throws IOException
     *         if an error occurs while writing to the stream.
     */
    @Override
    public void encodeBER(OutputStream outputStream) throws java.io.IOException {
        BER.encodeUnsignedInteger(outputStream, BER.GAUGE, getValue());
    }
}
