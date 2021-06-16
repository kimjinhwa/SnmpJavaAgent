/*_############################################################################
  _## 
  _##  SNMP4J - DTLSTMTest.java  
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
package org.snmp4j.transport;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.TSM;
import org.snmp4j.smi.*;
import org.snmp4j.transport.tls.DefaultTlsTmSecurityCallback;
import org.snmp4j.transport.tls.SecurityNameMapping;

import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Test DTLSTM with real networking.
 * @author Frank Fock
 */
public class DTLSTMTest {

    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setWarnEnabled(true);
    }

    private static final int TIMEOUT = 5000;

    private DTLSTM dtlstmCR;
    private DTLSTM dtlstmCS;
    private static final String SEC_NAME = "localhost";
    private static final OctetString SERVER_FINGER_PRINT =
            OctetString.fromHexString("4a:48:60:20:35:10:97:92:de:62:79:ae:85:b9:49:65:e9:03:6d:5a:f8:f3:70:41:9d:db:50:5a:76:3c:de:b5");
    private static final OctetString CLIENT_FINGER_PRINT = new OctetString("2");
    private static final byte[] MESSAGE = new byte[] { 0,1,2,3,4,5,6,7,8,9,10 };
    private static final byte[] MESSAGE_SCOPED_PDU =
            OctetString.fromHexString("02 01 00 02 01"
                    +" 00 30 46 30 17 06 0F 2B 06 01 04 01 A6 70 0A 01 01 04 01 01 02 00 42 04 05 75 8A 24 30 2B 06 09"
                    +" 2B 06 01 06 03 12 01 04 00 04 1E 70 65 57 61 64 66 6E 61 67 6E 65 72 67 72 44 46 41 41 48 41 72"
                    +" C3 A4 C3 B6 C3 9F 33 39 34", ' ').getValue();

    @Before
    public void setUp() throws Exception {

        dtlstmCS = new DTLSTM();
        dtlstmCR = new DTLSTM(new DtlsAddress("127.0.0.1/0"));
        URL keystoreUrl = getClass().getResource("dtls-cert.ks");
        String password = "snmp4j";
        dtlstmCS.setKeyStore(keystoreUrl.getFile());
        dtlstmCS.setKeyStorePassword(password);
        dtlstmCR.setKeyStore(keystoreUrl.getFile());
        dtlstmCR.setKeyStorePassword(password);
        dtlstmCS.setTrustStore(keystoreUrl.getFile());
        dtlstmCS.setTrustStorePassword(password);
        dtlstmCR.setTrustStore(keystoreUrl.getFile());
        dtlstmCR.setTrustStorePassword(password);
    }

    @After
    public void tearDown() throws Exception {
         dtlstmCR.close();
         dtlstmCS.close();
    }

    @Test
    public void sendMessage() throws Exception {
        final boolean[] messageReceived = { false };
        CertifiedTarget<UdpAddress> certifiedTarget = new CertifiedTarget<>(dtlstmCR.getListenAddress(),
                new OctetString(SEC_NAME), SERVER_FINGER_PRINT, CLIENT_FINGER_PRINT);
        TransportStateReference tmStateReference =
                new TransportStateReference(dtlstmCS,
                        dtlstmCR.getListenAddress(),
                        new OctetString(SEC_NAME),
                        SecurityLevel.authPriv,
                        SecurityLevel.undefined,
                        false, null, certifiedTarget);
        final TransportListener transportListener = new TransportListener() {
            public synchronized <A extends Address> void processMessage(TransportMapping<? super A> sourceTransport,
                                                                        A incomingAddress, ByteBuffer wholeMessage,
                                                                        TransportStateReference tmStateReference) {
                byte[] message = new byte[wholeMessage.limit()];
                System.arraycopy(wholeMessage.array(), 0, message, 0, message.length);
                assertArrayEquals(MESSAGE, message);
                messageReceived[0] = true;
                notify();
            }
        };
        dtlstmCR.addTransportListener(transportListener);
        dtlstmCR.listen();
        synchronized (transportListener) {
            dtlstmCS.sendMessage(dtlstmCR.getListenAddress(), MESSAGE, tmStateReference, 3000, 0);
            transportListener.wait(3200);
        }
        assertTrue(messageReceived[0]);
    }

    @Test
    public void sendMessageWithPDU() throws Exception {
        final boolean[] messageReceived = { false };
        CertifiedTarget<UdpAddress> certifiedTarget =
                new CertifiedTarget<>(new DtlsAddress(dtlstmCR.getListenAddress()),
                        new OctetString(SEC_NAME), SERVER_FINGER_PRINT, CLIENT_FINGER_PRINT);
        certifiedTarget.setTimeout(3500);
        certifiedTarget.setRetries(0);
        final CommandResponder commandResponder = new CommandResponder() {

            @Override
            public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                messageReceived[0] = true;
                this.notifyAll();
                event.setProcessed(true);
            }

        };
        DefaultTlsTmSecurityCallback securityCallback = new DefaultTlsTmSecurityCallback();
        securityCallback.addAcceptedSubjectDN("CN=www.snmp4j.org, OU=Unit-Test, O=AGENTPP, L=Stuttgart, ST=Baden-Wuerttemberg, C=DE");
        securityCallback.addSecurityNameMapping(
                OctetString.fromHexString("4a:48:60:20:35:10:97:92:de:62:79:ae:85:b9:49:65:e9:03:6d:5a:f8:f3:70:41:9d:db:50:5a:76:3c:de:b5"),
                SecurityNameMapping.CertMappingType.SANIpAddress,
                new OctetString("127.0.0.1"), new OctetString("localhost"));
        dtlstmCR.setSecurityCallback(securityCallback);
        Snmp snmpAgent = new Snmp(dtlstmCR);
        snmpAgent.addCommandResponder(commandResponder);
        ScopedPDU scopedPDU = new ScopedPDU();
        UnsignedInteger32 value1 = new UnsignedInteger32(91589156l);
        OctetString value2 = new OctetString("peWadfnagnergrDFAAHAräöß394");
        scopedPDU.add(new VariableBinding(SnmpConstants.snmp4jStatsRequestRetries, value1));
        scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapCommunity, value2));
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        Snmp snmp = new Snmp(dtlstmCS);
        ((MPv3)snmp.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM()));
        ((MPv3)snmpAgent.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM(localEngineID, false)));
        scopedPDU.setContextEngineID(localEngineID);
        snmpAgent.setLocalEngine(localEngineID.getValue(), 1, 1);
        snmpAgent.listen();
        synchronized (commandResponder) {
            snmp.send(scopedPDU, certifiedTarget);
            commandResponder.wait(4000);
        }
        assertTrue(messageReceived[0]);
        snmp.close();
        snmpAgent.close();
    }

    @Test
    public void sendMessagesWithPDU() throws Exception {
        final boolean[] messageReceived = { false, false };
        CertifiedTarget<UdpAddress> certifiedTarget =
                new CertifiedTarget<>(new DtlsAddress(dtlstmCR.getListenAddress()),
                        new OctetString(SEC_NAME), SERVER_FINGER_PRINT, CLIENT_FINGER_PRINT);
        certifiedTarget.setTimeout(3500);
        certifiedTarget.setRetries(0);
        final CommandResponder commandResponder = new CommandResponder() {

            @Override
            public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                messageReceived[event.getPDU().getVariableBindings().size()-2] = true;
                if (messageReceived[1]) {
                    this.notifyAll();
                }
                event.setProcessed(true);
            }

        };
        DefaultTlsTmSecurityCallback securityCallback = new DefaultTlsTmSecurityCallback();
        securityCallback.addAcceptedSubjectDN("CN=www.snmp4j.org, OU=Unit-Test, O=AGENTPP, L=Stuttgart, ST=Baden-Wuerttemberg, C=DE");
        securityCallback.addSecurityNameMapping(
                OctetString.fromHexString("4a:48:60:20:35:10:97:92:de:62:79:ae:85:b9:49:65:e9:03:6d:5a:f8:f3:70:41:9d:db:50:5a:76:3c:de:b5"),
                SecurityNameMapping.CertMappingType.SANIpAddress,
                new OctetString("127.0.0.1"), new OctetString("localhost"));
        dtlstmCR.setSecurityCallback(securityCallback);
        Snmp snmpAgent = new Snmp(dtlstmCR);
        snmpAgent.addCommandResponder(commandResponder);
        ScopedPDU scopedPDU = new ScopedPDU();
        UnsignedInteger32 value1 = new UnsignedInteger32(91589156l);
        OctetString value2 = new OctetString("peWadfnagnergrDFAAHAräöß394");
        scopedPDU.add(new VariableBinding(SnmpConstants.snmp4jStatsRequestRetries, value1));
        scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapCommunity, value2));
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        Snmp snmp = new Snmp(dtlstmCS);
        ((MPv3)snmp.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM()));
        ((MPv3)snmpAgent.getMessageDispatcher().getMessageProcessingModel(MPv3.ID)).setSecurityModels(
                new SecurityModels().addSecurityModel(new TSM(localEngineID, false)));
        scopedPDU.setContextEngineID(localEngineID);
        snmpAgent.setLocalEngine(localEngineID.getValue(), 1, 1);
        snmpAgent.listen();
        synchronized (commandResponder) {
            snmp.send(scopedPDU, certifiedTarget);
            ScopedPDU scopedPDU1 = (ScopedPDU) scopedPDU.clone();
            scopedPDU1.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("HelloWorld")));
            snmp.send(scopedPDU1, certifiedTarget);
            commandResponder.wait(4000);
        }
        assertTrue(messageReceived[0]);
        assertTrue(messageReceived[1]);
        snmp.close();
        snmpAgent.close();
    }

    @Test
    public void sendNotifyV3DTLSTM() throws Exception {
        DefaultTlsTmSecurityCallback securityCallback = new DefaultTlsTmSecurityCallback();
        securityCallback.addAcceptedSubjectDN("CN=www.snmp4j.org, OU=Unit-Test, O=AGENTPP, L=Stuttgart, ST=Baden-Wuerttemberg, C=DE");
        securityCallback.addSecurityNameMapping(
                OctetString.fromHexString("4a:48:60:20:35:10:97:92:de:62:79:ae:85:b9:49:65:e9:03:6d:5a:f8:f3:70:41:9d:db:50:5a:76:3c:de:b5"),
                SecurityNameMapping.CertMappingType.SANIpAddress,
                new OctetString("127.0.0.1"), new OctetString("localhost"));
        dtlstmCR.setSecurityCallback(securityCallback);
        SecurityModels.getInstance().addSecurityModel(new TSM());
        Snmp snmpCommandResponder = new Snmp(dtlstmCR);
        snmpCommandResponder.listen();
        CertifiedTarget<DtlsAddress> target = new CertifiedTarget<>(new DtlsAddress(dtlstmCR.getListenAddress()),
                new OctetString(SEC_NAME), SERVER_FINGER_PRINT, CLIENT_FINGER_PRINT);
        target.setTimeout(TIMEOUT);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.NOTIFICATION);
        pdu.setContextName(new OctetString("myContext"));
        SnmpTest.addTestVariableBindings(pdu, false, false, target.getVersion());
        Snmp snmp = new Snmp(dtlstmCS);
        pdu.setRequestID(new Integer32(snmp.getNextRequestID()));
        unconfirmedTest(snmpCommandResponder, snmp, dtlstmCS, target, pdu);
        snmp.close();
    }

    private <A extends Address> void unconfirmedTest(Snmp snmpCommandResponder, Snmp snmpCommandGenerator,
                                 TransportMapping<? super A> transportMappingCG, Target<A> target, PDU pdu)
            throws IOException {
        Map<Integer, List<SnmpTest.RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new SnmpTest.RequestResponse(pdu, null));
        SnmpTest.TestCommandResponder responder = new SnmpTest.TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target, transportMappingCG);
        assertNull(resp);
        try {
            for (int i=0; i<100 && !queue.isEmpty(); i++) {
                Thread.sleep(50);
            }
        } catch (InterruptedException iex) {
            // ignore
        }
        snmpCommandResponder.removeCommandResponder(responder);
        assertTrue(queue.isEmpty());
    }

}
