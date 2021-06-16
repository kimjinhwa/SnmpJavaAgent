/*_############################################################################
  _## 
  _##  SNMP4J - OctetStringTest.java  
  _## 
  _##  Copyright (C) 2003-2021  Frank Fock (SNMP4J.org)
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

package org.snmp4j.smi;

import junit.framework.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.Iterator;
import java.util.StringTokenizer;

import static org.junit.Assert.assertArrayEquals;

public class OctetStringTest extends TestCase {
    private static OID vacmAccessContextMatch = new OID("1.3.6.1.6.3.16.1.4.1.4.7.118.51.103.114.111.117.112.0.3.1");
    public static final String HEX_STRING = "1C:32:41:1C:4E:38";
    public static final String HEX16_STRING = "73878cd094fd8d2807c1af3f899ea93b67c5accb94fe96b52dba43520b498253";
    //public static final String HEX16_STRING_ALT = "73878cd094fd8d2807c1af3f899ea93b67c5accb94fe96b52dba43520b4982530";
    private OctetString octetString = null;

    @Before
    protected void setUp() throws Exception {
        super.setUp();
        octetString = new OctetString();
    }

    @After
    protected void tearDown() throws Exception {
        octetString = null;
        super.tearDown();
    }

    @Test
    public void testConstructors() {
        byte[] ba = {
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'};

        octetString = new OctetString(ba);

        assertEquals(octetString.toString(), "abcdefghi");

        octetString = new OctetString(ba, 2, 2);
        assertEquals(octetString.toString(), "cd");
    }

    @Test
    public void testSlip() {
        String s = "A short string with several delimiters  and a short word!";
        OctetString sp = new OctetString(s);
        Collection<OctetString> words = OctetString.split(sp, new OctetString("! "));
        StringTokenizer st = new StringTokenizer(s, "! ");
        for (Iterator<OctetString> it = words.iterator(); it.hasNext();) {
            OctetString os = it.next();
            assertEquals(os.toString(), st.nextToken());
        }
        assertFalse(st.hasMoreTokens());
    }

    @Test
    public void testIsPrintable() {
        OctetString nonPrintable = OctetString.fromHexString(HEX_STRING);
        assertFalse(nonPrintable.isPrintable());
    }

    @Test
    public void testFromCharArray() {
        char[] string = HEX_STRING.toCharArray();
        OctetString octetString = OctetString.fromCharArray(string);
        assertEquals(HEX_STRING, octetString.toString());
    }

    @Test
    public void testFromCharArrayByRadix() {
        char[] string = HEX_STRING.toCharArray();
        OctetString octetString = OctetString.fromCharArray(string, ':', 16);
        assertArrayEquals(new byte[] { 0x1c, 0x32, 0x41, 0x1c, 0x4e, 0x38 }, octetString.getValue());
    }

    @Test
    public void testFromIndex() {
        OctetString os = OctetString.fromIndex(vacmAccessContextMatch, 11, false);
        assertEquals("v3group", os.toString());
    }

    @Test
    public void testFroByteArrayRadix16() {
        OctetString octetString = OctetString.fromString(HEX16_STRING, 16);
        OctetString octetStringPair = OctetString.fromHexStringPairs(HEX16_STRING);
        assertEquals(octetStringPair.toHexString(), octetString.toHexString());
    }

}
