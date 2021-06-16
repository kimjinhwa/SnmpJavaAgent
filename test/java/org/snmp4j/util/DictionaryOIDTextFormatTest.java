/*_############################################################################
  _## 
  _##  SNMP4J - DictionaryOIDTextFormatTest.java  
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

package org.snmp4j.util;

import org.junit.Test;
import java.text.ParseException;

import static org.junit.Assert.*;

public class DictionaryOIDTextFormatTest {

    private DictionaryOIDTextFormat format =
            new DictionaryOIDTextFormat("sysDescr=1.3.6.1.2.1.1.1", "mgmt = 1.3.6.1.2",
                    "ifEntry=1.3.6.1.2.1.2.2.1", "ifAdminStatus=1.3.6.1.2.1.2.2.1.7");


    @Test
    public void format() {
        assertEquals("mgmt.1.1.3.6.1.2", format.format(new int[] { 1,3,6,1,2,1,1,3,6,1,2 }));
        assertEquals("mgmt.1.1", format.format(new int[] { 1,3,6,1,2,1,1 }));
        assertEquals("1.3.6.4", format.format(new int[] { 1,3,6,4 }));
        assertEquals("", format.format(new int[] { }));
        assertNull(format.format(null));
    }

    @Test
    public void parse() throws ParseException {
        assertArrayEquals(new int[] { 1,3,6,1,2,1,1,3,6,1,2 }, format.parse("mgmt.1.1.3.6.1.2"));
        assertArrayEquals(new int[] { 1,3,6,1,2,1,1 }, format.parse("mgmt.1.1"));
        assertArrayEquals(new int[] { 1,3,6,4 }, format.parse("1.3.6.4"));
        assertArrayEquals(new int[] { 1,3,6,1,2,1,2,2,1,7 }, format.parse("ifAdminStatus"));
        assertArrayEquals(new int[] { 1,3,6,1,2,1,2,2,1 }, format.parse("ifEntry"));
        assertArrayEquals(new int[] { 1,3,6,1,2,1,2,2,1,6 }, format.parse("ifEntry.6"));
        assertArrayEquals(new int[] { 1,3,6,1,2,1,2,2,1,7 }, format.parse("ifEntry.7"));
        assertArrayEquals(new int[] {  }, format.parse(""));
        assertArrayEquals(null, format.parse("."));
    }

    @Test(expected = ParseException.class)
    public void parseWithException() throws ParseException {
        try {
            format.parse("1.\"sometext.\"2.3");
        } catch (NumberFormatException nfe) {
            assertEquals("For input string: \"sometext\"", nfe.getMessage());
        }
    }
}