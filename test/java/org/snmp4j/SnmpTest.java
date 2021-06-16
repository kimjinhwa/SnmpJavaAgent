/*_############################################################################
  _## 
  _##  SNMP4J - SnmpTest.java  
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

package org.snmp4j;

import org.junit.*;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.event.CounterListener;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DummyTransport;
import org.snmp4j.transport.TransportMappings;
import org.snmp4j.util.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import static org.junit.Assert.*;

/**
 * Junit 4 test class for testing the {@link Snmp} class. The tests are run against a {@link DummyTransport} which
 * allows to directly link two virtual {@link TransportMapping}s used blocking queues.
 *
 * @author Frank Fock
 * @version 2.3.2
 */
public class SnmpTest {

    public static final String PRIV_PASSPHRASE_COUNT_DOWN = "_0987654321_";
    public static final String AUTH_PASSPHRASE_COUNT = "_12345678_";
    public static final String SHA_256_DES = "SHA256DES";
    public static final String SHA_224_AES_128 = "SHA224AES128";
    public static final String UNKNOWN_USER = "unknownUser";

    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setWarnEnabled(true);
    }

    private static final LogAdapter LOGGER = LogFactory.getLogger(SnmpTest.class);

    private static final OctetString SNMPv3_REPORT_PDU =
            OctetString.fromHexString("30:68:02:01:03:30:12:02:04:00:00:c2:90:02:04:00:00:04:00:04:01:00:02:01:03:04:21:30:1f:04:0b:80:00:42:c7:03:54:10:ec:ca:34:a7:02:04:00:00:00:04:02:04:00:04:5e:d7:04:00:04:00:04:00:30:2c:04:00:04:00:a8:82:00:24:02:04:00:00:00:00:02:01:00:02:01:00:30:82:00:14:30:12:06:0a:2b:06:01:06:03:0f:01:01:04:00:41:04:00:00:08:53");

    private DummyTransport<UdpAddress> transportMappingCG;
    private AbstractTransportMapping<UdpAddress> transportMappingCR;
    private Snmp snmpCommandGenerator;
    private Snmp snmpCommandResponder;
    private CommunityTarget<UdpAddress> communityTarget =
            new CommunityTarget<>((UdpAddress) GenericAddress.parse("udp:127.0.0.1/161"),
                    new OctetString("public"));
    private UserTarget<UdpAddress> userTarget =
            new UserTarget<>((UdpAddress) GenericAddress.parse("udp:127.0.0.1/161"),
                    new OctetString(SHA_256_DES), new byte[0]);

    static {
        SNMP4JSettings.setForwardRuntimeExceptions(true);
        SNMP4JSettings.setSnmp4jStatistics(SNMP4JSettings.Snmp4jStatistics.extended);
        try {
            setupBeforeClass();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @BeforeClass
    public static void setupBeforeClass() throws Exception {
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();
        System.setProperty(TransportMappings.TRANSPORT_MAPPINGS, "dummy-transports.properties");
        Assert.assertEquals(DummyTransport.class,
                TransportMappings.getInstance().createTransportMapping(GenericAddress.parse("udp:127.0.0.1/161")).getClass());
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        SecurityProtocols.setSecurityProtocols(null);
        System.clearProperty(TransportMappings.TRANSPORT_MAPPINGS);
        SNMP4JSettings.setExtensibilityEnabled(false);
    }

    @Before
    public void setUp() throws Exception {
        transportMappingCG = new DummyTransport<>(new UdpAddress("127.0.0.1/4967"));
        transportMappingCR = transportMappingCG.getResponder(new UdpAddress("127.0.0.1/161"));
        snmpCommandGenerator = new Snmp(transportMappingCG);
        MPv3 mpv3CG = (MPv3) snmpCommandGenerator.getMessageDispatcher().getMessageProcessingModel(MPv3.ID);
        mpv3CG.setLocalEngineID(MPv3.createLocalEngineID(new OctetString("generator")));
        mpv3CG.setCurrentMsgID(MPv3.randomMsgID(new Random().nextInt(MPv3.MAX_MESSAGE_ID)));
        SecurityModels.getInstance().addSecurityModel(
                new USM(SecurityProtocols.getInstance(), new OctetString(mpv3CG.getLocalEngineID()), 0));
        snmpCommandResponder = new Snmp(transportMappingCR);
        CounterSupport counterSupportResponder = new CounterSupport();
        snmpCommandResponder.setCounterSupport(counterSupportResponder);

        counterSupportResponder.addCounterListener(new DefaultCounterListener());
        CounterSupport.getInstance().addCounterListener(new DefaultCounterListener());
        SecurityModels respSecModels = new SecurityModels() {

        };
        MPv3 mpv3CR = (MPv3) snmpCommandResponder.getMessageDispatcher().getMessageProcessingModel(MPv3.ID);
        mpv3CR.setCounterSupport(counterSupportResponder);
        mpv3CR.setLocalEngineID(MPv3.createLocalEngineID(new OctetString("responder")));
        USM usmCR = new USM(SecurityProtocols.getInstance(), new OctetString(mpv3CR.getLocalEngineID()), 0);
        usmCR.setCounterSupport(counterSupportResponder);
        respSecModels.addSecurityModel(usmCR);
        mpv3CR.setSecurityModels(respSecModels);
        addDefaultUsers();
    }

    private void addDefaultUsers() {
        OctetString longUsername = new OctetString(new byte[32]);
        Arrays.fill(longUsername.getValue(), (byte) 0x20);
        addCommandGeneratorUsers(longUsername);
        addCommandResponderUsers(longUsername);
    }

    private void addCommandResponderUsers(OctetString longUsername) {
        snmpCommandResponder.getUSM().addUser(
                new UsmUser(new OctetString(SHA_256_DES), AuthHMAC256SHA384.ID, new OctetString("AUTH_PASSPHRASE_COUNT"),
                        PrivDES.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
        snmpCommandResponder.getUSM().addUser(
                new UsmUser(new OctetString(SHA_224_AES_128), AuthHMAC128SHA224.ID, new OctetString("AUTH_PASSPHRASE_COUNT"),
                        PrivAES128.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
        snmpCommandResponder.getUSM().addUser(
                new UsmUser(longUsername, AuthHMAC256SHA384.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        PrivDES.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
    }

    private void addCommandGeneratorUsers(OctetString longUsername) {
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString("SHA256DES"), AuthHMAC256SHA384.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        PrivDES.ID, new OctetString("PRIV_KEY_COUNT_DOWN")));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(UNKNOWN_USER), AuthHMAC256SHA384.ID, new OctetString("AUTH_PASSPHRASE_COUNT"),
                        PrivDES.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(longUsername, AuthHMAC256SHA384.ID, new OctetString("AUTH_PASSPHRASE_COUNT"),
                        PrivDES.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
    }

    @After
    public void tearDown() throws Exception {
        snmpCommandGenerator.close();
        snmpCommandResponder.close();
    }

    @Test
    public void testSmiConstants() {
        int[] definedConstants = new int[]{
                SMIConstants.SYNTAX_INTEGER,
                SMIConstants.SYNTAX_OCTET_STRING,
                SMIConstants.SYNTAX_NULL,
                SMIConstants.SYNTAX_OBJECT_IDENTIFIER,
                SMIConstants.SYNTAX_IPADDRESS,
                SMIConstants.SYNTAX_INTEGER32,
                SMIConstants.SYNTAX_COUNTER32,
                SMIConstants.SYNTAX_GAUGE32,
                SMIConstants.SYNTAX_UNSIGNED_INTEGER32,
                SMIConstants.SYNTAX_TIMETICKS,
                SMIConstants.SYNTAX_OPAQUE,
                SMIConstants.SYNTAX_COUNTER64
        };
        String[] constantNames = new String[]{
                "INTEGER",
                "OCTET_STRING",
                "NULL",
                "OBJECT_IDENTIFIER",
                "IPADDRESS",
                "INTEGER32",
                "COUNTER32",
                "GAUGE32",
                "UNSIGNED_INTEGER32",
                "TIMETICKS",
                "OPAQUE",
                "COUNTER64"
        };
        for (int i = 0; i < definedConstants.length; i++) {
            LOGGER.debug(constantNames[i] + " = " + definedConstants[i]);
        }
        for (int i = 0; i < definedConstants.length; i++) {
            LOGGER.debug(constantNames[i]);
        }
        for (int i = 0; i < definedConstants.length; i++) {
            LOGGER.debug(definedConstants[i]);
        }
    }

    @Test
    public void testListen() throws Exception {
        Assert.assertEquals(transportMappingCG.isListening(), false);
        snmpCommandGenerator.listen();
        Assert.assertEquals(transportMappingCG.isListening(), true);
    }

    @Test
    public void testClose() throws Exception {
        Assert.assertEquals(transportMappingCG.isListening(), false);
        snmpCommandGenerator.close();
        Assert.assertEquals(transportMappingCG.isListening(), false);
        testListen();
        snmpCommandGenerator.close();
        Assert.assertEquals(transportMappingCG.isListening(), false);
    }

    @Test
    public void testGetV1() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version1);
        CounterListener counterListener = createSimpleWaitCounterListenerExtended(target);
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        PDU pdu = new PDU();
        pdu.setType(PDU.GET);
        addTestVariableBindings(pdu, false, false, target.getVersion());
        syncRequestTest(target, pdu);
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }

    private CounterListener createSimpleWaitCounterListenerExtended(final Target<?> target) {
        return new CounterListener() {
            private int status;

            @Override
            public void incrementCounter(CounterEvent event) {
                switch (status++) {
                    case 0:
                        Assert.assertEquals(SnmpConstants.snmp4jStatsRequestWaitTime, event.getOid());
                        assertNull(event.getIndex());
                        assertTrue(event.getCurrentValue().toLong() > 0);
                        break;
                    case 1:
                        Assert.assertEquals(SnmpConstants.snmp4jStatsReqTableWaitTime, event.getOid());
                        Assert.assertEquals(target.getAddress(), event.getIndex());
                        assertTrue(event.getCurrentValue().toLong() > 0);
                        break;
                }
            }
        };
    }

    @Test
    public void testGetV2c() throws Exception {
        final CommunityTarget<?> target = (CommunityTarget) communityTarget.duplicate();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version2c);
        CounterListener counterListener = createSimpleWaitCounterListenerExtended(target);
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        PDU pdu = new PDU();
        pdu.setType(PDU.GET);
        addTestVariableBindings(pdu, false, false, target.getVersion());
        syncRequestTest(target, pdu);
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }

    @Test
    public void testTableUtilsOutOfOrderSingleThreadedDelay0() throws Exception {
        runTableUtilsTest(false, 0, 10,
                2, 5, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsOutOfOrderMultiThreadedDelay0() throws Exception {
        runTableUtilsTest(true, 0, 10,
                2, 5, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsNewRowsMultiThreadedDelay0() throws Exception {
        runTableUtilsTest(true, 0, 40,
                4, 4, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsOutOfOrderMultiThreadedDelay200() throws Exception {
        runTableUtilsTest(true, 200, 10,
                2, 5, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsOnRowMultiThreadedDelay0() throws Exception {
        runTableUtilsTest(true, 0, 1,
                1, 5, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsStopDelay0() throws Exception {
        runTableUtilsTest(true, 0, 50,
                2, 6, 0, 0, 0, 0);
    }

    @Test
    public void testTableUtilsWrongLexicographicOrderMax1Delay0() throws Exception {
        runTableUtilsTest(true, 0, 30,
                1, 1, 6, 0, 0, TableEvent.STATUS_WRONG_ORDER);
    }

    @Test
    public void testTableUtilsWrongLexicographicOrderLoopOnFirstDelay0() throws Exception {
        runTableUtilsTest(true, 0, 30,
                1, 1, 2, 0, -1, TableEvent.STATUS_WRONG_ORDER);
    }

    @Test
    public void testTableUtilsWrongLexicographicOrderDelay0() throws Exception {
        runTableUtilsTest(true, 0, 30,
                1, 6, 15, 0, 0, TableEvent.STATUS_WRONG_ORDER);
    }

    @Test
    public void testTableUtilsWrongLexicographicOrderMax2Delay0() throws Exception {
        runTableUtilsTest(true, 0, 12,
                1, 6, 9, 2, 2, TableEvent.STATUS_WRONG_ORDER);
    }

    @Test
    public void testTableUtilsWrongLexicographicOrderNoCheckDelay0() throws Exception {
        // without check, 4 more rows will be returned.
        runTableUtilsTest(true, 0, 12,
                1, 6, 9, -1, 4, TableEvent.STATUS_TIMEOUT);
    }

    private void runTableUtilsTest(boolean multiThreadedRequest, long delayMillisFirstColumnPDU,
                                   int maxRows, int numPDUsPerRow,
                                   int maxColumnsPerPDU, int lexiLoopStart,
                                   int maxLexiErrors, int eventOffset, int expectedStatus) throws IOException {
        final String OID_PREFIX = "1.3.6.1.4976.1.";
        final CommunityTarget<?> target = (CommunityTarget) communityTarget.duplicate();
        target.setTimeout(1000);
        MessageDispatcher origMessageDispatcher = snmpCommandResponder.getMessageDispatcher();
        ThreadPool threadPool = ThreadPool.create("ResponderPool", 4);
        snmpCommandResponder.setMessageDispatcher(new MultiThreadedMessageDispatcher(threadPool, origMessageDispatcher));
        target.setVersion(SnmpConstants.version2c);
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(100);
        for (int r = 0; r <= maxRows; r++) {
            for (int s = 0; s < numPDUsPerRow; s++) {
                PDU responsePdu = new PDU();
                PDU requestPdu = new PDU();
                requestPdu.setType(PDU.GETNEXT);
                responsePdu.setType(PDU.RESPONSE);
                for (int i = 1; i < maxColumnsPerPDU + 1; i++) {
                    int c = s * maxColumnsPerPDU + i;
                    if ((lexiLoopStart > 0) && (r == lexiLoopStart)) {
                        requestPdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + ((2 * r) - 1)), new Null()));
                        responsePdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + (2 * r - (lexiLoopStart - 1))),
                                new OctetString("" + 1 + "." + c)));
                    } else if ((lexiLoopStart > 0) && (r > lexiLoopStart)) {
                        requestPdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + ((2 * r - (lexiLoopStart - 1)) - 2)), new Null()));
                        responsePdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + (2 * r - (lexiLoopStart - 1))),
                                new OctetString("" + 1 + "." + c)));
                    } else {
                        addReqAndRespColOnRow(maxRows, r, responsePdu, requestPdu, c);
                    }
                }
                responsePdu.setRequestID(new Integer32(requestPdu.getVariableBindings().hashCode()));
                requestPdu.setRequestID(responsePdu.getRequestID());
                RequestResponse rr = new RequestResponse(requestPdu, responsePdu);
                if (s == 0) {
                    rr.delay = delayMillisFirstColumnPDU;
                }
                rr.response.setType(PDU.RESPONSE);
                queue.computeIfAbsent(responsePdu.getRequestID().getValue(), k -> new ArrayList<>()).add(rr);
                LOGGER.debug("Request-Pair: " + rr);
            }
        }
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        List<OID> colOIDs = new ArrayList<>();
        for (int i = 1; i <= numPDUsPerRow * maxColumnsPerPDU; i++) {
            colOIDs.add(new OID(OID_PREFIX + i));
        }
        final Object tableSync = new Object();
        final List<TableEvent> tableEvents = Collections.synchronizedList(new ArrayList<>(maxRows + 1));
        TableUtils tableUtils = new TableUtils(snmpCommandGenerator, new DefaultPDUFactory(PDU.GETNEXT)) {
            @Override
            protected TableRequest createTableRequest(Target<?> target, OID[] columnOIDs, TableListener listener,
                                                      Object userObject, OID lowerBoundIndex, OID upperBoundIndex,
                                                      SparseTableMode sparseTableMode) {
                return new TableRequest(target, columnOIDs, listener,
                        userObject, lowerBoundIndex, upperBoundIndex, sparseTableMode) {
                    @Override
                    public <A extends Address> void onResponse(ResponseEvent<A> event) {
                        LOGGER.debug("Table response:" + event);
                        super.onResponse(event);
                    }
                };

            }
        };
        tableUtils.setCheckLexicographicOrdering((lexiLoopStart > 0) && (maxLexiErrors >= 0));
        tableUtils.setIgnoreMaxLexicographicRowOrderingErrors(maxLexiErrors);
        tableUtils.setSendColumnPDUsMultiThreaded(multiThreadedRequest);
        tableUtils.setMaxNumColumnsPerPDU(maxColumnsPerPDU);
        tableUtils.getTable(target, colOIDs.toArray(new OID[0]), new TableListener() {
            @Override
            public boolean next(TableEvent event) {
                LOGGER.debug(event);
                tableEvents.add(event);
                return true;
            }

            @Override
            public void finished(TableEvent event) {
                LOGGER.debug(event);
                tableEvents.add(event);
                synchronized (tableSync) {
                    tableSync.notify();
                }
            }

            @Override
            public boolean isFinished() {
                return false;
            }
        }, null, null, null);
        synchronized (tableSync) {
            try {
                tableSync.wait(15000);
            } catch (InterruptedException iex) {
                // ignore
            }
        }
        int eventLimit = (lexiLoopStart > 0) ? lexiLoopStart + 1 : maxRows + 1;
        eventLimit += eventOffset;
        Assert.assertEquals(eventLimit, tableEvents.size());
        Assert.assertEquals(expectedStatus, tableEvents.get(eventLimit - 1).getStatus());
        if (maxLexiErrors >= 0) {
            tableEvents.remove(eventLimit - 1);
            int i = 1;
            for (TableEvent tableEvent : tableEvents) {
                if (tableEvent.getStatus() != TableEvent.STATUS_WRONG_ORDER) {
                    Assert.assertEquals(new OID(new int[]{i}), tableEvent.getIndex());
                    for (int j = 0; j < numPDUsPerRow * maxColumnsPerPDU; j++) {
                        OID oid = new OID(OID_PREFIX + (j + 1));
                        oid.append(tableEvent.getIndex().get(0));
                        Assert.assertEquals(oid, tableEvent.getColumns()[j].getOid());
                    }
                    i += 2;
                }
            }
        }
    }

    private void addReqAndRespColOnRow(int maxRows, int r, PDU responsePdu, PDU requestPdu, int c) {
        if (r == 0) {
            requestPdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c), new Null()));
        } else {
            requestPdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + ((2 * r) - 1)), new Null()));
        }
        if ((r >= maxRows)) {
            responsePdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + (c + 1) + "." + 1),
                    new OctetString("" + 1 + "." + (c + 1))));
        } else {
            responsePdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + c + "." + ((2 * r) + 1)),
                    new OctetString("" + (r + 1) + "." + c)));
        }
    }

    @Test
    public void testDiscoverV3Anomaly65KUserName() throws Exception {
        CounterListener counterListener = new CounterListener() {
            @Override
            public void incrementCounter(CounterEvent event) {
                Assert.assertEquals(SnmpConstants.snmp4jStatsRequestWaitTime, event.getOid());
                Assert.assertEquals(communityTarget, event.getIndex());
                assertTrue(event.getCurrentValue().toLong() > 0);
            }
        };
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        OctetString longUsername = new OctetString(new byte[65416]);
        Arrays.fill(longUsername.getValue(), (byte) 0x20);
        UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setSecurityName(longUsername);
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        try {
            syncRequestTest(target, pdu);
            // fail here
            Assert.assertFalse(true);
        } catch (MessageException mex) {
            Assert.assertEquals(SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME, mex.getSnmp4jErrorStatus());
        }
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }


    @Test
    public void testGetV3() throws Exception {
        UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        syncRequestTest(target, pdu);
    }

    @Test
    public void testGetV3LocalizedKeysInUserTarget() throws Exception {
        DirectUserTarget<?> target = new DirectUserTarget<UdpAddress>(userTarget);
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        byte[] authoritativeEngineID = snmpCommandResponder.getLocalEngineID();
        byte[] authKey = SecurityProtocols.getInstance().passwordToKey(AuthHMAC128SHA224.ID,
                new OctetString(AUTH_PASSPHRASE_COUNT), authoritativeEngineID);
        byte[] privKey = SecurityProtocols.getInstance().passwordToKey(PrivAES128.ID, AuthHMAC128SHA224.ID,
                new OctetString(PRIV_PASSPHRASE_COUNT_DOWN), authoritativeEngineID);
        target.setAuthenticationKey(new OctetString(authKey));
        target.setPrivacyKey(new OctetString(privKey));
        target.setAuthenticationProtocol(SecurityProtocols.getInstance().getAuthenticationProtocol(AuthHMAC128SHA224.ID));
        target.setPrivacyProtocol(SecurityProtocols.getInstance().getPrivacyProtocol(PrivAES128.ID));
        // Use username not in sender USM:
        target.setSecurityName(new OctetString(SHA_224_AES_128));
        target.setAuthoritativeEngineID(authoritativeEngineID);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        syncRequestTest(target, pdu);
    }

    @Test
    public void testGetV3_RFC3414_3_2_3() throws Exception {
        final UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityName(new OctetString(UNKNOWN_USER));
        target.setAuthoritativeEngineID(new byte[0]);
        target.setSecurityLevel(SecurityLevel.noAuthNoPriv.getSnmpValue());
        final ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        CounterListener counterListener = createTimeoutCounterListenerExtended(target);
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        // test it
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        // first try should return local error
        try {
            ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
            PDU expectedResponse = makeReport(pdu, new VariableBinding(SnmpConstants.usmStatsUnknownUserNames, new Counter32(1)));
            // request ID will be 0 because ScopedPDU could not be parsed:
            expectedResponse.setRequestID(new Integer32(0));
            ((ScopedPDU) expectedResponse).setContextEngineID(new OctetString(snmpCommandResponder.getUSM().getLocalEngineID()));
            Assert.assertEquals(expectedResponse, resp.getResponse());
        } catch (MessageException mex) {
            Assert.assertEquals(SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME, mex.getSnmp4jErrorStatus());
        }
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }

    @Test
    public void testGetV3_RFC3414_3_2_4() throws Exception {
        final UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityName(new OctetString("unknownSecurityName"));
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        addTestVariableBindings(pdu, false, false, target.getVersion());
        CounterListener counterListener = new CounterListener() {
            private int state = 0;

            @Override
            public void incrementCounter(CounterEvent event) {
                if (!event.getOid().startsWith(SnmpConstants.snmp4jStatsRequest)) {
                    switch (state++) {
                        case 0:
                        case 1:
                            assertTrue(SnmpConstants.usmStatsUnknownEngineIDs.equals(event.getOid()) ||
                                    SnmpConstants.usmStatsUnknownUserNames.equals(event.getOid()));
                            break;
                        case 2:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsRequestTimeouts, event.getOid());
                            assertNull(event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                        case 3:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsReqTableTimeouts, event.getOid());
                            Assert.assertEquals(target.getAddress(), event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                    }
                }
            }
        };
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        // test it
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        // first try should return local error
        try {
            ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
            assertNull(resp);
        } catch (MessageException mex) {
            Assert.assertEquals(SnmpConstants.SNMPv3_USM_UNKNOWN_SECURITY_NAME, mex.getSnmp4jErrorStatus());
        }
        // second try: remote error
        target.setSecurityName(new OctetString(UNKNOWN_USER));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(UNKNOWN_USER), AuthHMAC128SHA224.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        PrivAES128.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));

        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
        PDU expectedResponse = makeReport(pdu, new VariableBinding(SnmpConstants.usmStatsUnknownUserNames, new Counter32(1)));
        // request ID will be 0 because ScopedPDU could not be parsed:
        expectedResponse.setRequestID(new Integer32(0));
        ((ScopedPDU) expectedResponse).setContextEngineID(new OctetString(snmpCommandResponder.getUSM().getLocalEngineID()));
        Assert.assertEquals(expectedResponse, resp.getResponse());
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);

    }

    @Test
    public void testUsmSeparation() {
        Assert.assertNotSame(snmpCommandGenerator.getUSM(), snmpCommandResponder.getUSM());
    }

    private CounterListener createTimeoutCounterListenerExtended(final Target<?> target) {
        return new CounterListener() {
            private int state = 0;

            @Override
            public void incrementCounter(CounterEvent event) {
                if (!event.getOid().startsWith(SnmpConstants.snmp4jStatsRequest)) {
                    switch (state++) {
                        case 0:
                            Assert.assertEquals(SnmpConstants.usmStatsUnknownUserNames, event.getOid());
                            break;
                        case 1:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsRequestTimeouts, event.getOid());
                            assertNull(event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                        case 2:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsReqTableTimeouts, event.getOid());
                            Assert.assertEquals(target.getAddress(), event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                    }
                }
            }

            ;
        };
    }

    @Test
    public void testGetV3_RFC3414_3_2_5() throws Exception {
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        final UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        addTestVariableBindings(pdu, false, false, target.getVersion());
        CounterListener counterListener = createTimeoutCounterListenerExtended(target);
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        // test it
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        // first try should return local error
        target.setSecurityName(new OctetString(SHA_224_AES_128));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(SHA_224_AES_128), AuthHMAC128SHA224.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        null, null));
        try {
            ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
            // This will be hit if engine ID discovery is enabled
            assertNull(resp.getResponse());
        } catch (MessageException mex) {
            // This will only happen if no engine ID discovery is needed
            Assert.assertEquals(SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL, mex.getSnmp4jErrorStatus());
        }
        // second try without engine ID discovery
        try {
            ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
            // This will be hit if engine ID discovery is enabled
            assertNull(resp);
        } catch (MessageException mex) {
            // This will only happen if no engine ID discovery is needed
            Assert.assertEquals(SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL, mex.getSnmp4jErrorStatus());
        }
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.noAuthNoPrivIfNeeded);
        // third try: remote error
        snmpCommandGenerator.getUSM().removeAllUsers(new OctetString(SHA_224_AES_128));
        snmpCommandResponder.getUSM().removeAllUsers(new OctetString(SHA_224_AES_128));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(SHA_224_AES_128), AuthHMAC128SHA224.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        PrivAES128.ID, new OctetString("$secure$")));
        snmpCommandResponder.getUSM().addUser(
                new UsmUser(new OctetString(SHA_224_AES_128), AuthHMAC128SHA224.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        null, null));
        target.setAuthoritativeEngineID(snmpCommandResponder.getLocalEngineID());
        pdu.setContextEngineID(new OctetString(snmpCommandResponder.getLocalEngineID()));
        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
        PDU expectedResponse =
                makeReport(pdu, new VariableBinding(SnmpConstants.usmStatsUnsupportedSecLevels, new Counter32(1)));
        // request ID will be 0 because ScopedPDU could not be parsed:
        expectedResponse.setRequestID(new Integer32(0));
        ((ScopedPDU) expectedResponse).setContextEngineID(new OctetString(snmpCommandResponder.getLocalEngineID()));
        Assert.assertEquals(expectedResponse, resp.getResponse());

        // Test standard behavior
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.standard);
        target.setAuthoritativeEngineID(snmpCommandResponder.getLocalEngineID());
        pdu.setContextEngineID(new OctetString(snmpCommandResponder.getLocalEngineID()));
        resp = snmpCommandGenerator.send(pdu, target);
        // We expect null (delay) as response, because sender has no matching privacy protocol to return message.
        assertNull(resp.getResponse());
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }

    @Test
    public void testGetV3_RFC3414_3_2_6() throws Exception {
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        UserTarget<?> target = (UserTarget) userTarget.clone();
        target.setTimeout(2000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityName(new OctetString(SHA_256_DES));
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        addTestVariableBindings(pdu, false, false, target.getVersion());
        // test it
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(SHA_256_DES), AuthHMAC256SHA384.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                        PrivDES.ID, new OctetString("_09876543#1_")));

        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        final long[] wrongDigestEvents = new long[]{0L};
        CounterListener counterListener = new CounterListener() {
            @Override
            public void incrementCounter(CounterEvent event) {
                if (event.getOid().equals(SnmpConstants.usmStatsWrongDigests)) {
                    wrongDigestEvents[0] = event.getCurrentValue().toLong();
                }
            }
        };
        snmpCommandResponder.getCounterSupport().addCounterListener(counterListener);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();

        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
        // no response because receiver cannot decode the message.
        assertNull(resp.getResponse());

        // next try no authentication, so with standard report strategy we will not receive a report
        snmpCommandGenerator.getUSM().removeAllUsers(new OctetString(SHA_256_DES));
        snmpCommandGenerator.getUSM().addUser(
                new UsmUser(new OctetString(SHA_256_DES), AuthHMAC256SHA384.ID, new OctetString("_12345#78_"),
                        PrivDES.ID, new OctetString("_09876543#1_")));
        target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);

        resp = snmpCommandGenerator.send(pdu, target);
        assertNull(resp.getResponse());

        // same but with relaxed report strategy
        SNMP4JSettings.setReportSecurityLevelStrategy(SNMP4JSettings.ReportSecurityLevelStrategy.noAuthNoPrivIfNeeded);
        resp = snmpCommandGenerator.send(pdu, target);
//        Assert.assertNull(resp.getResponse());
        PDU expectedResponse = makeReport(pdu, new VariableBinding(SnmpConstants.usmStatsWrongDigests, new Counter32(3)));
        expectedResponse.setRequestID(new Integer32(0));
        ((ScopedPDU) expectedResponse).setContextEngineID(new OctetString(snmpCommandResponder.getUSM().getLocalEngineID()));
        Assert.assertEquals(expectedResponse, resp.getResponse());
        // The usmStatsWrongDigests counter was incremented to 3 because we had already two before
        Assert.assertEquals(3L, wrongDigestEvents[0]);
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
    }

    private void syncRequestTest(Target<?> target, PDU pdu) throws IOException {
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target);
        PDU expectedResponse = makeResponse(pdu, target.getVersion());
        Assert.assertEquals(expectedResponse, resp.getResponse());
    }

    private void asyncRequestTest(Target<?> target, PDU pdu) throws IOException {
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        final AsyncResponseListener asyncResponseListener = new AsyncResponseListener(queue.size());
        snmpCommandGenerator.send(pdu, target, null, asyncResponseListener);
        synchronized (asyncResponseListener) {
            try {
                asyncResponseListener.wait(20000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private void asyncRequestTestWithRetry(final Target<?> target, PDU pdu, long timeout, int retries) throws IOException {
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion()), retries));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        responder.setTimeout(timeout);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        final AsyncResponseListener asyncResponseListener = new AsyncResponseListener(queue.size());
        snmpCommandGenerator.send(pdu, target, null, asyncResponseListener);
        synchronized (asyncResponseListener) {
            try {
                asyncResponseListener.wait(20000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    private <A extends Address> void unconfirmedTest(TransportMapping<? super A> transportMappingCG,
                                                     Target<A> target, PDU pdu) throws IOException {
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(2);
        queue.computeIfAbsent(pdu.getRequestID().getValue(),
                k -> new ArrayList<>()).add(new RequestResponse(pdu, makeResponse(pdu, target.getVersion())));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandResponder.listen();
        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target, transportMappingCG);
        assertNull(resp);
        try {
            Thread.sleep(500);
        } catch (InterruptedException iex) {
            // ignore
        }
        snmpCommandResponder.removeCommandResponder(responder);
        assertTrue(queue.isEmpty());
    }

    private void unconfirmedTestNullResult(Target<UdpAddress> target, PDU pdu) throws IOException {
        Map<Integer, List<RequestResponse>> queue = Collections.emptyMap();
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandResponder.listen();
        ResponseEvent<?> resp = snmpCommandGenerator.send(pdu, target, transportMappingCG);
        assertNull(resp);
        try {
            Thread.sleep(500);
        } catch (InterruptedException iex) {
            // ignore
        }
        Assert.assertFalse(responder.isAnyResponse());
    }

    private PDU makeResponse(PDU pdu, int version) {
        PDU responsePDU = (PDU) pdu.clone();
        responsePDU.setType(PDU.RESPONSE);
        responsePDU.setErrorStatus(PDU.noError);
        responsePDU.setErrorIndex(0);
        responsePDU.getVariableBindings().clear();
        addTestVariableBindings(responsePDU, true, true, version);
        return responsePDU;
    }

    private PDU makeReport(PDU pdu, VariableBinding reportVariable) {
        PDU responsePDU = (PDU) pdu.clone();
        responsePDU.setType(PDU.REPORT);
        responsePDU.setErrorStatus(PDU.noError);
        responsePDU.setErrorIndex(0);
        responsePDU.getVariableBindings().clear();
        responsePDU.add(reportVariable);
        return responsePDU;
    }

    public static void addTestVariableBindings(PDU pdu, boolean withValue, boolean withNull, int version) {
        pdu.add(new VariableBinding(new OID(SnmpConstants.sysDescr), (withValue) ?
                new OctetString("Test string with öä°#+~§ and normal text.1234567890123456789012345678901234567890{}") : Null.instance));
        pdu.add(new VariableBinding(new OID(SnmpConstants.sysObjectID), (withValue) ? new OID("1.3.6.1.4.1.4976") : Null.instance));
        if (version > SnmpConstants.version1) {
            pdu.add(new VariableBinding(new OID("1.1"), (withValue) ? new Counter64(1234567890123456789L) : Null.instance));
        }
        pdu.add(new VariableBinding(new OID("1.2"), (withValue) ? new Integer32(Integer.MAX_VALUE) : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.1"), (withValue) ? new UnsignedInteger32(((long) Integer.MIN_VALUE & 0xFFFFFF)) : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.2"), (withValue) ? new Counter32(Integer.MAX_VALUE * 2L) : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.3"), (withValue) ? new Gauge32(Integer.MAX_VALUE / 2) : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.4"), (withValue) ? new TimeTicks(12345678) : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.5"), (withValue) ? new IpAddress("127.0.0.1") : Null.instance));
        pdu.add(new VariableBinding(new OID("1.3.1.6.6"), (withValue) ? new Opaque(new byte[]{0, -128, 56, 48, 0, 1}) : Null.instance));
        if (withNull) {
            pdu.add(new VariableBinding(new OID("1.3.1.6.7"), (withValue) ? Null.noSuchInstance : Null.instance));
        }
    }

    @Test(timeout = 30000)
    public void testGetNextV3Async() throws Exception {
        Target<UdpAddress> target = userTarget;
        target.setTimeout(50000L);
        target.setRetries(0);
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(10000);
        for (int i = 0; i < 99; i++) {
            ScopedPDU pdu = new ScopedPDU();
            pdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + i), new Integer32(i)));
            pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
            RequestResponse rr = new RequestResponse(pdu, (PDU) pdu.clone());
            rr.response.setType(PDU.RESPONSE);
            queue.computeIfAbsent(pdu.getRequestID().getValue(), k -> new ArrayList<>()).add(rr);
            pdu.get(0).setVariable(Null.instance);
        }
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        int n = 0;
        final AsyncResponseListener asyncResponseListener = new AsyncResponseListener(queue.size());
        List<List<RequestResponse>> requests = new ArrayList<>(queue.values());
        synchronized (asyncResponseListener) {
            for (List<RequestResponse> rr : requests) {
                for (RequestResponse rrr : rr) {
                    snmpCommandGenerator.send(rrr.request, target, transportMappingCG, n, asyncResponseListener);
                    n++;
                }
            }
            asyncResponseListener.wait(20000);
        }
    }

    @Test(timeout = 30000)
    public void testGetNextV3AsyncWrongUserAnd0RequestID() throws Exception {
        final Target<UdpAddress> target = userTarget;
        target.setTimeout(50000L);
        target.setRetries(0);
        target.setSecurityName(new OctetString("unknownUser"));
        ScopedPDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID("1.3.6.1.4976.1.1"), new Integer32(1)));
        pdu.setRequestID(new Integer32(1));
        pdu.get(0).setVariable(Null.instance);
        final Map<Integer, List<RequestResponse>> responseMap = new HashMap<>(10000);
        ScopedPDU reportPDU = new ScopedPDU();
        reportPDU.setContextEngineID(new OctetString(snmpCommandResponder.getLocalEngineID()));
        reportPDU.setRequestID(new Integer32(0));
        reportPDU.setType(PDU.REPORT);
        responseMap.computeIfAbsent(1, k -> new ArrayList<>()).add(new RequestResponse(pdu, reportPDU));
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, responseMap);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        ResponseListener responseListener = new ResponseListener() {

            @Override
            public synchronized <A extends Address> void onResponse(ResponseEvent<A> event) {
                target.setRetries(1);
                this.notify();
            }
        };
        synchronized (responseListener) {
            snmpCommandGenerator.send(pdu, target, transportMappingCG, null, responseListener);
            responseListener.wait(2000);
        }
        Assert.assertEquals(1, target.getRetries());
    }


    @Test(timeout = 30000)
    public void testGetNextV3AsyncUserChange() throws Exception {
        Target<UdpAddress> target = userTarget;
        target.setTimeout(50000L);
        target.setRetries(0);
        Map<Integer, List<RequestResponse>> queue = new HashMap<>(10000);
        for (int i = 0; i < 999; i++) {
            ScopedPDU pdu = new ScopedPDU();
            pdu.add(new VariableBinding(new OID("1.3.6.1.4976.1." + i), new Integer32(i)));
            pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
            RequestResponse rr = new RequestResponse(pdu, (PDU) pdu.clone());
            rr.response.setType(PDU.RESPONSE);
            queue.computeIfAbsent(pdu.getRequestID().getValue(), k -> new ArrayList<>()).add(rr);
            pdu.get(0).setVariable(Null.instance);

        }
        TestCommandResponder responder = new TestCommandResponder(snmpCommandResponder, queue);
        snmpCommandResponder.addCommandResponder(responder);
        snmpCommandGenerator.listen();
        snmpCommandResponder.listen();
        int n = 0;
        final AsyncResponseListener asyncResponseListener = new AsyncResponseListener(queue.size());
        List<List<RequestResponse>> requests = new ArrayList<>(queue.values());
        for (List<RequestResponse> rr : requests) {
            for (RequestResponse rrr : rr) {
                snmpCommandGenerator.send(rrr.request, target, transportMappingCG, n, asyncResponseListener);
                n++;
            }
//      Thread.sleep(1L);
        }
        synchronized (asyncResponseListener) {
            snmpCommandResponder.getUSM().removeAllUsers(new OctetString("SHADES2"));
            asyncResponseListener.wait(1000);
            snmpCommandResponder.getUSM().addUser(
                    new UsmUser(new OctetString("SHA256DES2"), AuthSHA.ID, new OctetString(AUTH_PASSPHRASE_COUNT),
                            PrivDES.ID, new OctetString(PRIV_PASSPHRASE_COUNT_DOWN)));
        }
    }

    @Test
    public void testTrapV1() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version1);
        PDUv1 pdu = new PDUv1();
        pdu.setType(PDU.V1TRAP);
        pdu.setAgentAddress(new IpAddress("127.0.0.1"));
        pdu.setEnterprise(new OID("1.3.6.1.4.1.4976"));
        pdu.setSpecificTrap(9);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        unconfirmedTest(transportMappingCG, target, pdu);
    }

    @Test
    public void testTrapV2WithV1() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version1);
        PDU pdu = new PDU();
        pdu.setType(PDU.NOTIFICATION);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        unconfirmedTestNullResult(target, pdu);
    }

    @Test
    public void testTrapV2WithV1Allowed() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version1);
        PDU pdu = new PDU();
        pdu.setType(PDU.NOTIFICATION);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        SNMP4JSettings.setAllowSNMPv2InV1(true);
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        unconfirmedTest(transportMappingCG, target, pdu);
    }

    @Test
    public void testNotifyV2c() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version2c);
        PDU pdu = new PDU();
        pdu.setType(PDU.NOTIFICATION);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        unconfirmedTest(transportMappingCG, target, pdu);
    }

    @Test
    public void testNotifyV3() throws Exception {
        notifyV3(transportMappingCG);
    }

    private void notifyV3(TransportMapping<UdpAddress> transportMappingCG) throws IOException {
        UserTarget<UdpAddress> target = (UserTarget<UdpAddress>) userTarget.duplicate();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.NOTIFICATION);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        unconfirmedTest(transportMappingCG, target, pdu);
    }

    @Test
    public void testInformV2c() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version2c);
        PDU pdu = new PDU();
        pdu.setType(PDU.INFORM);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        syncRequestTest(target, pdu);
    }

    @Test
    public void testInformV3() throws Exception {
        UserTarget<UdpAddress> target = (UserTarget<UdpAddress>) userTarget.duplicate();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.INFORM);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        syncRequestTest(target, pdu);
    }

    @Test
    public void testInformV2cAsync() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version2c);
        PDU pdu = new PDU();
        pdu.setType(PDU.INFORM);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        asyncRequestTest(target, pdu);
    }

    @Test
    public void testInformV2cAsyncWithRetry() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version2c);
        target.setTimeout(1500);
        target.setRetries(2);
        PDU pdu = new PDU();
        pdu.setType(PDU.INFORM);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        asyncRequestTestWithRetry(target, pdu, 1000, 1);
    }

    @Test
    public void testInformV3Async() throws Exception {
        UserTarget<UdpAddress> target = (UserTarget<UdpAddress>) userTarget.duplicate();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.INFORM);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        asyncRequestTest(target, pdu);
    }

    @Test
    public void testInformV3AsyncWithRetry() throws Exception {
        SNMP4JSettings.Snmp4jStatistics snmp4jStatistics = SNMP4JSettings.getSnmp4jStatistics();
        SNMP4JSettings.setSnmp4jStatistics(SNMP4JSettings.Snmp4jStatistics.extended);
        final UserTarget<UdpAddress> target = (UserTarget<UdpAddress>) userTarget.duplicate();
        target.setRetries(2);
        target.setTimeout(1000);
        target.setVersion(SnmpConstants.version3);
        CounterListener counterListener = new CounterListener() {
            private int state = 0;

            @Override
            public void incrementCounter(CounterEvent event) {
                if (!event.getOid().startsWith(SnmpConstants.snmp4jStatsRequest)) {
                    switch (state++) {
                        case 0:
                            Assert.assertEquals(SnmpConstants.usmStatsUnknownEngineIDs, event.getOid());
                            break;
                        case 1:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsRequestRetries, event.getOid());
                            assertNull(event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                        case 2:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsReqTableRetries, event.getOid());
                            Assert.assertEquals(target.getAddress(), event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                        case 3:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsRequestWaitTime, event.getOid());
                            assertNull(event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                        case 4:
                            Assert.assertEquals(SnmpConstants.snmp4jStatsReqTableWaitTime, event.getOid());
                            Assert.assertEquals(target.getAddress(), event.getIndex());
                            assertTrue(event.getCurrentValue().toLong() > 0);
                            break;
                    }
                }
            }
        };
        snmpCommandGenerator.getCounterSupport().addCounterListener(counterListener);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.INFORM);
        pdu.setContextName(new OctetString("myContext"));
        addTestVariableBindings(pdu, false, false, target.getVersion());
        pdu.setRequestID(new Integer32(snmpCommandGenerator.getNextRequestID()));
        asyncRequestTestWithRetry(target, pdu, 1000, 2);
        snmpCommandGenerator.getCounterSupport().removeCounterListener(counterListener);
        SNMP4JSettings.setSnmp4jStatistics(snmp4jStatistics);
    }


    @Test
    public void testSetV1() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version1);
        PDU pdu = new PDU();
        pdu.setType(PDU.SET);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        syncRequestTest(target, pdu);
    }

    @Test
    public void testSetV2c() throws Exception {
        CommunityTarget<UdpAddress> target = (CommunityTarget<UdpAddress>) communityTarget.duplicate();
        target.setVersion(SnmpConstants.version2c);
        PDU pdu = new PDU();
        pdu.setType(PDU.SET);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        syncRequestTest(target, pdu);
    }

    @Test
    public void testSetV3() throws Exception {
        UserTarget<UdpAddress> target = (UserTarget<UdpAddress>) userTarget.duplicate();
        target.setTimeout(10000);
        target.setVersion(SnmpConstants.version3);
        ScopedPDU pdu = new ScopedPDU();
        pdu.setContextName(new OctetString("myContext"));
        pdu.setType(PDU.SET);
        addTestVariableBindings(pdu, true, false, target.getVersion());
        syncRequestTest(target, pdu);
    }

    @Test
    public void testSend() throws Exception {

    }

    @Test
    public void testMPv3EngineIdCache() throws Exception {
        Snmp backupSnmp = snmpCommandGenerator;
        int backupEngineIdCacheSize = ((MPv3) snmpCommandResponder.getMessageProcessingModel(MPv3.ID)).getMaxEngineIdCacheSize();
        ((MPv3) snmpCommandResponder.getMessageProcessingModel(MPv3.ID)).setMaxEngineIdCacheSize(5);
        OctetString longUsername = new OctetString(new byte[32]);
        Arrays.fill(longUsername.getValue(), (byte) 0x20);
        for (int i = 0; i < 7; i++) {
            LOGGER.debug("Testing iteration " + i);
            DummyTransport<UdpAddress> transportMappingCG = new DummyTransport<UdpAddress>(new UdpAddress("127.0.0.1/" + (i + 30000)));
            snmpCommandGenerator = new Snmp(transportMappingCG);
            TransportMapping<UdpAddress> responderTM = transportMappingCG.getResponder(new UdpAddress("127.0.0.1/161"));
            snmpCommandResponder.addTransportMapping(responderTM);
            transportMappingCG.listen();
            MPv3 mpv3CG = (MPv3) snmpCommandGenerator.getMessageDispatcher().getMessageProcessingModel(MPv3.ID);
            mpv3CG.setLocalEngineID(MPv3.createLocalEngineID(new OctetString("generator")));
            SecurityModels.getInstance().addSecurityModel(
                    new USM(SecurityProtocols.getInstance(), new OctetString(mpv3CG.getLocalEngineID()), 0));
            addCommandGeneratorUsers(longUsername);
            notifyV3(transportMappingCG);
            snmpCommandResponder.removeTransportMapping(responderTM);
            assertTrue(((MPv3) snmpCommandResponder.getMessageProcessingModel(MPv3.ID)).getEngineIdCacheSize() <= 5);
        }
        snmpCommandGenerator = backupSnmp;
        ((MPv3) snmpCommandResponder.getMessageProcessingModel(MPv3.ID)).setMaxEngineIdCacheSize(backupEngineIdCacheSize);
    }

    @Test
    public void testRandomMsgID() throws Exception {
        int engineBoots = 1;
        int randomMsgID1 = MPv3.randomMsgID(engineBoots);
        Assert.assertEquals(0x00010000, randomMsgID1 & 0xFFFF0000);
        engineBoots = 0xABCDEF12;
        int randomMsgID2 = MPv3.randomMsgID(engineBoots);
        Assert.assertEquals(0xEF120000, randomMsgID2 & 0xFFFF0000);
        Assert.assertNotSame(randomMsgID1 & 0xFFFF0000, randomMsgID2 & 0xFFFF0000);
    }

    @Test
    public void testMPv3PrepareMessageWithLongLength() {
        MessageDispatcher md = new MessageDispatcherImpl();
        MPv3 mPv3 = new MPv3();
        Integer32 mp = new Integer32();
        Integer32 secModel = new Integer32();
        Integer32 secLevel = new Integer32();
        MutablePDU pdu = new MutablePDU();
        PduHandle sendPduHandle = new PduHandle();
        Integer32 maxSizeResponsePDU = new Integer32();
        StatusInformation statusInfo = new StatusInformation();
        MutableStateReference<UdpAddress> stateReferene = new MutableStateReference<>();
        TransportStateReference tmStateReference = new TransportStateReference(transportMappingCR,
                transportMappingCR.getListenAddress(), null, null,
                null, false, null);
        BERInputStream wholeMsg = new BERInputStream(ByteBuffer.wrap(SNMPv3_REPORT_PDU.toByteArray()));
        OctetString secName = new OctetString();
        int result = mPv3.prepareDataElements(md, new UdpAddress(), wholeMsg, tmStateReference,
                mp, secModel, secName, secLevel, pdu, sendPduHandle, maxSizeResponsePDU, statusInfo, stateReferene);
        assertEquals(SnmpConstants.SNMP_MP_UNKNOWN_MSGID, result);
    }


    public static class TestCommandResponder implements CommandResponder {

        private Map<Integer, List<RequestResponse>> expectedPDUs;
        private boolean anyResponse;
        private long timeout = 0;
        private Snmp snmpCommandResponder;

        public TestCommandResponder(Snmp snmpCommandResponder, PDU request, PDU response) {
            this.snmpCommandResponder = snmpCommandResponder;
            this.expectedPDUs = new HashMap<Integer, List<RequestResponse>>(1);
            expectedPDUs.put(request.getRequestID().getValue(), Collections.singletonList(new RequestResponse(request, response)));
        }

        public TestCommandResponder(Snmp snmpCommandResponder, Map<Integer, List<RequestResponse>> expectedPDUs) {
            this.snmpCommandResponder = snmpCommandResponder;
            this.expectedPDUs = expectedPDUs;
        }

        public long getTimeout() {
            return timeout;
        }

        public void setTimeout(long timeout) {
            this.timeout = timeout;
        }

        public boolean isAnyResponse() {
            return anyResponse;
        }

        @Override
        public synchronized <A extends Address> void processPdu(CommandResponderEvent<A> event) {
            PDU pdu = event.getPDU();
            if (expectedPDUs.size() > 0) {
                assertNotNull(pdu);
                List<RequestResponse> expectedResponseList = expectedPDUs.remove(pdu.getRequestID().getValue());
                if (expectedResponseList == null) {
                    int hashCode = pdu.getVariableBindings().hashCode();
                    expectedResponseList = expectedPDUs.get(hashCode);
                    LOGGER.debug("Expected request " + pdu.getRequestID().getValue() +
                            " not found directly, using hasCode " + hashCode + ":=" + expectedResponseList);
                    if (expectedResponseList == null || expectedResponseList.isEmpty()) {
                        LOGGER.warn("Expected request not found for " + event + " with hashCode = " + hashCode);
                        return;
                    }
                }
                assertFalse(expectedResponseList.isEmpty());
                RequestResponse expected = expectedResponseList.remove(0);
                assertNotNull(expected);
                assertEquals(expected.request.getVariableBindings(), pdu.getVariableBindings());
                if (expected.retries > 0) {
                    expected.retries--;
                    expectedPDUs.computeIfAbsent(pdu.getRequestID().getValue(),
                            k -> new ArrayList<>()).add(0, expected);
                }
                try {
                    // adjust context engine ID after engine ID discovery
                    if (expected.response != null && pdu.isConfirmedPdu()) {
                        if (expected.request instanceof ScopedPDU) {
                            ScopedPDU scopedPDU = (ScopedPDU) expected.request;
                            OctetString contextEngineID = scopedPDU.getContextEngineID();
                            if ((contextEngineID != null) && (contextEngineID.length() > 0)) {
                                ((ScopedPDU) expected.response).setContextEngineID(contextEngineID);
                            }
                        }
                        if (timeout > 0) {
                            try {
                                Thread.sleep(timeout);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                        if (expected.delay > 0) {
                            try {
                                Thread.sleep(expected.delay);
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                        expected.response.setRequestID(pdu.getRequestID());
                        snmpCommandResponder.getMessageDispatcher().returnResponsePdu(
                                event.getMessageProcessingModel(), event.getSecurityModel(),
                                event.getSecurityName(), event.getSecurityLevel(),
                                expected.response, event.getMaxSizeResponsePDU(),
                                event.getStateReference(), new StatusInformation());
                        anyResponse = true;
                    }
                } catch (MessageException e) {
                    assertNotNull(e);
                    System.out.println("Failed to send response on PDU: "+pdu);
                    e.printStackTrace();
                }
            }
        }
    }

    public static class RequestResponse {
        public PDU request;
        public PDU response;
        public int retries;
        public long delay;

        public RequestResponse(PDU request, PDU response) {
            this.request = request;
            this.response = response;
        }

        public RequestResponse(PDU request, PDU response, int retries) {
            this(request, response);
            this.retries = retries;
        }

        @Override
        public String toString() {
            return "RequestResponse{" +
                    "request=" + request +
                    ", response=" + response +
                    '}';
        }
    }

    private class AsyncResponseListener implements ResponseListener {

        private int maxCount = 0;
        private int received = 0;
        private Set<Integer32> receivedIDs = new HashSet<Integer32>();

        public AsyncResponseListener(int maxCount) {
            this.maxCount = maxCount;
        }

        @Override
        public synchronized <A extends Address> void onResponse(ResponseEvent<A> event) {
            ((Session) event.getSource()).cancel(event.getRequest(), this);
            assertTrue(receivedIDs.add(event.getRequest().getRequestID()));
            ++received;
            assertNotNull(event.getResponse());
            assertNotNull(event.getResponse().get(0));
            assertNotNull(event.getResponse().get(0).getVariable());
            if (received >= maxCount) {
                notify();
            }
            assertFalse((received > maxCount));
        }
    }

}
