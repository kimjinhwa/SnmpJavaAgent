/*_############################################################################
  _## 
  _##  SNMP4J - TestPrivAES.java  
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


package org.snmp4j.security;

import junit.framework.*;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import static org.junit.Assert.assertArrayEquals;


public class TestPrivAES extends TestCase {
    public static final String SECRET_MESSAGE = "This is a secret message, nobody is allowed to read it!";
    private SecurityProtocols secProts;

    public static String asHex(byte buf[]) {
        return new OctetString(buf).toHexString();
    }

    public TestPrivAES() {
    }

    public TestPrivAES(String p0) {
        super(p0);
    }

    protected void setUp() {
    }

    protected void tearDown() {
    }

    public static void testCrypt() {
        PrivAES128 pd = new PrivAES128();
        DecryptParams pp = new DecryptParams();
        byte[] key = {
                (byte) 0x66, (byte) 0x95, (byte) 0xfe, (byte) 0xbc,
                (byte) 0x92, (byte) 0x88, (byte) 0xe3, (byte) 0x62,
                (byte) 0x82, (byte) 0x23, (byte) 0x5f, (byte) 0xc7,
                (byte) 0x15, (byte) 0x1f, (byte) 0x12, (byte) 0x84//,
                /*
                (byte) 0x97, (byte) 0xb3, (byte) 0x8f, (byte) 0x3f,
                (byte) 0x50, (byte) 0x5E, (byte) 0x07, (byte) 0xEB,
                (byte) 0x9A, (byte) 0xF2, (byte) 0x55, (byte) 0x68,
                (byte) 0xFA, (byte) 0x1F, (byte) 0x5D, (byte) 0xBE*/
        };
        byte[] plaintext = SECRET_MESSAGE.getBytes();
        byte[] ciphertext = null;
        byte[] decrypted = null;
        int engine_boots = 0xdeadc0de;
        int engine_time = 0xbeefdede;

        ciphertext = pd.encrypt(plaintext, 0, plaintext.length, key, engine_boots, engine_time, pp);
        decrypted = pd.decrypt(ciphertext, 0, ciphertext.length, key, engine_boots, engine_time, pp);

        assertEquals(asHex(plaintext), asHex(decrypted));
        assertEquals(8, pp.length);
    }

    public void testAesKeyExtension() {
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
        byte[] key =
                SecurityProtocols.getInstance().passwordToKey(PrivAES256.ID, AuthSHA.ID, new OctetString("maplesyrup"),
                        new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte)0,
                                (byte) 0, (byte) 0, (byte) 0, (byte)0,
                                (byte) 0, (byte) 0, (byte) 0, (byte)2 });
        assertEquals("66:95:fe:bc:92:88:e3:62:82:23:5f:c7:15:1f:12:84:97:b3:8f:3f:50:5e:07:eb:9a:f2:55:68:fa:1f:5d:be",
                new OctetString(key).toHexString());
    }

    public void testSecurityProtocolsAddDefaultProtocols() {
        SNMP4JSettings.setExtensibilityEnabled(true);
        System.setProperty(SecurityProtocols.SECURITY_PROTOCOLS_PROPERTIES, "SecurityProtocolsTest.properties");
        SecurityProtocols.getInstance().addDefaultProtocols();
        OID aes192AGENTppID = new OID("1.3.6.1.6.3.10.1.2.20");
        OID aes256AGENTppID = new OID("1.3.6.1.6.3.10.1.2.21");
        assertNotNull(SecurityProtocols.getInstance().getPrivacyProtocol(aes192AGENTppID));
        assertNotNull(SecurityProtocols.getInstance().getPrivacyProtocol(aes256AGENTppID));
        assertEquals(aes192AGENTppID, SecurityProtocols.getInstance().getPrivacyProtocol(aes192AGENTppID).getID());
        assertEquals(aes256AGENTppID, SecurityProtocols.getInstance().getPrivacyProtocol(aes256AGENTppID).getID());
    }

    public void testCiscoVsBlumenthalAES256() {
        PrivAES256 blumenthalAES256 = new PrivAES256();
        PrivAES256With3DESKeyExtension ciscoAES56 = new PrivAES256With3DESKeyExtension();
        PrivacyProtocol[] protocols = new PrivacyProtocol[] { blumenthalAES256, ciscoAES56 };
        byte[] plainText = SECRET_MESSAGE.getBytes();
        byte[] secret = "maplesyrup secret PassPhrase with more than 32 bytes".getBytes();
        byte[][] cipher = new byte[2][];
        byte[][] decrypted = new byte[2][];
        byte[][] crossDecrypted = new byte[2][];
        int engine_boots = 0xdeadc0de;
        int engine_time = 0xbeefdede;
        byte[] engineID = MPv3.createLocalEngineID();

        AuthenticationProtocol authenticationProtocol = new AuthHMAC192SHA256();
        byte[] key = authenticationProtocol.passwordToKey(new OctetString(secret), engineID);
        for (int i=0; i<protocols.length; i++) {
            DecryptParams decryptParams = new DecryptParams();
            cipher[i] = protocols[i].encrypt(plainText, 0, plainText.length, key, engine_boots,
                    engine_time, decryptParams);
            decrypted[i] = protocols[i].decrypt(cipher[i], 0, cipher[i].length, key, engine_boots, engine_time,
                    decryptParams);
            crossDecrypted[i] = protocols[1-i].decrypt(cipher[i], 0, cipher[i].length, key, engine_boots, engine_time,
                    decryptParams);
        }
        assertArrayEquals(plainText, decrypted[0]);
        assertArrayEquals(plainText, decrypted[1]);
        // Test that AES256 IETF (Blumenthal Draft) is compatible with AES256 Cisco (3DES key extension) if keys are
        // long enough (You need AuthHMAC192SHA256 for AES256, which is a 32 bytes key length)
        assertArrayEquals(plainText, crossDecrypted[0]);
        assertArrayEquals(plainText, crossDecrypted[1]);
    }
}
