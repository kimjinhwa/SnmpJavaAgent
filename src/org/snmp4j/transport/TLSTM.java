/*_############################################################################
  _## 
  _##  SNMP4J - TLSTM.java  
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

import org.snmp4j.SNMP4JSettings;
import org.snmp4j.TransportStateReference;
import org.snmp4j.asn1.BER;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.CounterSupport;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.*;
import org.snmp4j.transport.tls.*;
import org.snmp4j.util.CommonTimer;
import org.snmp4j.util.SnmpConfigurator;
import org.snmp4j.util.WorkerTask;

import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * The {@code TLSTM} implements the Transport Layer Security
 * Transport Mapping (TLS-TM) as defined by RFC 5953
 * with the new IO API and {@link javax.net.ssl.SSLEngine}.
 * <p>
 * It uses a single thread for processing incoming and outgoing messages.
 * The thread is started when the {@code listen} method is called, or
 * when an outgoing request is sent using the {@code sendMessage} method.
 *
 * @author Frank Fock
 * @version 3.5.0
 * @since 2.0
 */
public class TLSTM extends TcpTransportMapping<TLSTM.SocketEntry> implements X509TlsTransportMappingConfig {

    private static final LogAdapter logger = LogFactory.getLogger(TLSTM.class);
    public static final int TLS_MAX_FRAGMENT_SIZE = 16384;

    private WorkerTask server;
    private ServerThread serverThread;

    private CommonTimer socketCleaner;
    // 1 minute default timeout
    private long connectionTimeout = 60000;
    private long nextSessionID = 1;

    private SSLEngineConfigurator sslEngineConfigurator;

    private final TlsTmSecurityCallbackProxy<X509Certificate> securityCallback = new TlsTmSecurityCallbackProxy<>();
    private CounterSupport counterSupport;

    /**
     * The default supported TLS protocol versions.
     */
    public static final String DEFAULT_TLSTM_PROTOCOLS = "TLSv1.2";
    public static final int MAX_TLS_PAYLOAD_SIZE = 32 * 1024;

    private String localCertificateAlias;
    private String keyStore;
    private String keyStorePassword;
    private String trustStore;
    private String trustStorePassword;
    private String[] tlsProtocols;
    private TLSTMTrustManagerFactory trustManagerFactory = new DefaultTLSTMTrustManagerFactory();
    private int tlsMaxFragmentSize;

    /**
     * Creates a default TCP transport mapping with the server for incoming
     * messages disabled.
     *
     * @throws UnknownHostException
     *         if the local host cannot be determined.
     */
    public TLSTM() throws UnknownHostException {
        super(new TlsAddress(InetAddress.getLocalHost(), 0));
        this.counterSupport = CounterSupport.getInstance();
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        this.tlsMaxFragmentSize = TLS_MAX_FRAGMENT_SIZE;
    }

    /**
     * Creates a TLS transport mapping with the server for incoming
     * messages bind to the given address. The {@code securityCallback}
     * needs to be specified before {@link #listen()} is called.
     *
     * @param address
     *         the address to bind for incoming requests.
     *
     * @throws java.io.IOException
     *         on failure of binding a local port.
     */
    public TLSTM(TlsAddress address) throws IOException {
        this(address, true);
    }

    /**
     * Creates a TLS transport mapping with the server for incoming
     * messages bind to the given address. The {@code securityCallback}
     * needs to be specified before {@link #listen()} is called.
     *
     * @param address
     *         the address to bind for incoming requests.
     * @param serverEnabled
     *         defines the role of the underlying {@link SSLEngine}. Setting this to {@code false} enables
     *         the {@link SSLEngine#setUseClientMode(boolean)}.
     *
     * @throws java.io.IOException
     *         on failure of binding a local port.
     * @since 3.2.0
     */
    public TLSTM(TlsAddress address, boolean serverEnabled) throws IOException {
        super(address);
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        this.serverEnabled = serverEnabled;
        this.counterSupport = CounterSupport.getInstance();
        this.tlsMaxFragmentSize = TLS_MAX_FRAGMENT_SIZE;
        setupTrustManagerFactory();
    }

    private void setupTrustManagerFactory() throws IOException {
        try {
            if (Class.forName("javax.net.ssl.X509ExtendedTrustManager") != null) {
                Class<?> trustManagerFactoryClass =
                        Class.forName("org.snmp4j.transport.tls.TLSTMExtendedTrustManagerFactory");
                Constructor<?> c = trustManagerFactoryClass.getConstructors()[0];
                TLSTMTrustManagerFactory trustManagerFactory =
                        (TLSTMTrustManagerFactory) c.newInstance(CounterSupport.getInstance(), securityCallback);
                setTrustManagerFactory(trustManagerFactory);
            }
        } catch (ClassNotFoundException ex) {
            //throw new IOException("Failed to load TLSTMTrustManagerFactory: "+ex.getMessage(), ex);
        } catch (InvocationTargetException ex) {
            throw new IOException("Failed to init TLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            throw new IOException("Failed to setup TLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        } catch (IllegalAccessException ex) {
            throw new IOException("Failed to access TLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        } catch (InstantiationException ex) {
            throw new IOException("Failed to instantiate TLSTMTrustManagerFactory: " + ex.getMessage(), ex);
        }
    }

    /**
     * Creates a TLS transport mapping that binds to the given address
     * (interface) on the local host.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the TcpAddress instance that describes the server address to listen
     *         on incoming connection requests.
     *
     * @throws java.io.IOException
     *         if the given address cannot be bound.
     */
    public TLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback,
                 TlsAddress serverAddress) throws IOException {
        this(securityCallback, serverAddress, CounterSupport.getInstance());
    }

    /**
     * Creates a TLS transport mapping that binds to the given address
     * (interface) on the local host.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the TcpAddress instance that describes the server address to listen
     *         on incoming connection requests.
     * @param counterSupport
     *         The CounterSupport instance to be used to count events created by this
     *         TLSTM instance. To get a default instance, use
     *         {@link CounterSupport#getInstance()}.
     *
     * @throws java.io.IOException
     *         if the given address cannot be bound.
     */
    public TLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback,
                 TlsAddress serverAddress, CounterSupport counterSupport) throws IOException {
        this(securityCallback, serverAddress, counterSupport, true);
    }

    /**
     * Creates a TLS transport mapping that binds to the given address
     * (interface) on the local host.
     *
     * @param securityCallback
     *         a security name callback to resolve X509 certificates to tmSecurityNames.
     * @param serverAddress
     *         the TcpAddress instance that describes the server address to listen
     *         on incoming connection requests.
     * @param counterSupport
     *         The CounterSupport instance to be used to count events created by this
     *         TLSTM instance. To get a default instance, use
     *         {@link CounterSupport#getInstance()}.
     * @param serverEnabled
     *         defines the role of the underlying {@link SSLEngine}. Setting this to {@code false} enables
     *         the {@link SSLEngine#setUseClientMode(boolean)}.
     *
     * @throws java.io.IOException
     *         if the given address cannot be bound.
     * @since 3.2.0
     */
    public TLSTM(TlsTmSecurityCallback<X509Certificate> securityCallback,
                 TlsAddress serverAddress, CounterSupport counterSupport, boolean serverEnabled) throws IOException {
        this(serverAddress, serverEnabled);
        super.maxInboundMessageSize = MAX_TLS_PAYLOAD_SIZE;
        this.securityCallback.setTlsTmSecurityCallback(securityCallback);
        this.counterSupport = counterSupport;
    }

    public String getLocalCertificateAlias() {
        if (localCertificateAlias == null) {
            return System.getProperty(SnmpConfigurator.P_TLS_LOCAL_ID, null);
        }
        return localCertificateAlias;
    }

    /**
     * Gets the {@link TransportType} this {@code TransportMapping} supports depending on {@link #isServerEnabled()}.
     *
     * @return {@link TransportType#any} if {@link #isServerEnabled()} is {@code true} and
     * {@link TransportType#sender} otherwise.
     * @since 3.2.0
     */
    @Override
    public TransportType getSupportedTransportType() {
        return (serverEnabled ? TransportType.any : TransportType.sender);
    }

    /**
     * Gets the maximum fragment size of supported for this transport mapping when acting as TLS server.
     * @return
     *    the maximum TLS fragment size as defined by RFC 6066 section 4.
     */
    public int getTlsMaxFragmentSize() {
        return tlsMaxFragmentSize;
    }

    /**
     * Sets the maximum TLS fragment size that this transport mapping should support as server. There is no need to
     * change that from the default {@link #TLS_MAX_FRAGMENT_SIZE} unless, a new Java version allows to set the
     * maximum fragment size to a lower value.
     * @param tlsMaxFragmentSize
     *    a value as defined by RFC 6066 section 4.
     * @since 3.0.5
     */
    public void setTlsMaxFragmentSize(int tlsMaxFragmentSize) {
        this.tlsMaxFragmentSize = tlsMaxFragmentSize;
    }

    /**
     * Gets the TLS protocols supported by this transport mapping.
     * @return
     *    an array of TLS protocol (version) names supported by the SunJSSE provider.
     * @deprecated Use {@link #getProtocolVersions} instead.
     */
    @Deprecated
    public String[] getTlsProtocols() {
        return getProtocolVersions();
    }

    /**
     * Sets the TLS protocols/versions that TLSTM should use during handshake.
     * The default is defined by {@link #DEFAULT_TLSTM_PROTOCOLS}.
     *
     * @param tlsProtocols
     *         an array of TLS protocol (version) names supported by the SunJSSE provider.
     *         The order in the array defines which protocol is tried during handshake
     *         first.
     *
     * @since 2.0.3
     * @deprecated Use {@link #setProtocolVersions(String[])} instead.
     */
    @Deprecated
    public void setTlsProtocols(String[] tlsProtocols) {
        setProtocolVersions(tlsProtocols);
    }

    /**
     * Sets the TLS protocols/versions that TLSTM should use during handshake.
     * The default is defined by {@link #DEFAULT_TLSTM_PROTOCOLS}.
     *
     * @param protocolVersions
     *         an array of TLS protocol (version) names supported by the SunJSSE provider.
     *         The order in the array defines which protocol is tried during handshake
     *         first.
     * @since 3.0
     */
    @Override
    public void setProtocolVersions(String[] protocolVersions) {
        this.tlsProtocols = protocolVersions;
    }

    @Override
    public String[] getProtocolVersions() {
        if (tlsProtocols == null) {
            String s = System.getProperty(getProtocolVersionPropertyName(), DEFAULT_TLSTM_PROTOCOLS);
            return s.split(",");
        }
        return tlsProtocols;
    }

    /**
     * Returns the property name that is used by this transport mapping to determine the protocol versions
     * from system properties.
     *
     * @return a property name like {@link SnmpConfigurator#P_TLS_VERSION} or
     * {@link SnmpConfigurator#P_DTLS_VERSION}.
     * @since 3.0
     */
    @Override
    public String getProtocolVersionPropertyName() {
        return SnmpConfigurator.P_TLS_VERSION;
    }

    public String getKeyStore() {
        if (keyStore == null) {
            return System.getProperty("javax.net.ssl.keyStore");
        }
        return keyStore;
    }

    public void setKeyStore(String keyStore) {
        this.keyStore = keyStore;
    }

    public String getKeyStorePassword() {
        if (keyStorePassword == null) {
            return System.getProperty("javax.net.ssl.keyStorePassword");
        }
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustStore() {
        if (trustStore == null) {
            return System.getProperty("javax.net.ssl.trustStore");
        }
        return trustStore;
    }

    public void setTrustStore(String trustStore) {
        this.trustStore = trustStore;
    }

    public String getTrustStorePassword() {
        if (trustStorePassword == null) {
            return System.getProperty("javax.net.ssl.trustStorePassword");
        }
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    /**
     * Sets the certificate alias used for client and server authentication
     * by this TLSTM. Setting this property to a value other than {@code null}
     * filters out any certificates which are not in the chain of the given
     * alias.
     *
     * @param localCertificateAlias
     *         a certificate alias which filters a single certification chain from
     *         the {@code javax.net.ssl.keyStore} key store to be used to
     *         authenticate this TLS transport mapping. If {@code null} no
     *         filtering appears, which could lead to more than a single chain
     *         available for authentication by the peer, which would violate the
     *         TLSTM standard requirements.
     */
    public void setLocalCertificateAlias(String localCertificateAlias) {
        this.localCertificateAlias = localCertificateAlias;
    }

    public CounterSupport getCounterSupport() {
        return counterSupport;
    }

    @Override
    public Class<? extends Address> getSupportedAddressClass() {
        return TlsAddress.class;
    }

    public TlsTmSecurityCallback<X509Certificate> getSecurityCallback() {
        return securityCallback.getTlsTmSecurityCallback();
    }

    public void setSecurityCallback(TlsTmSecurityCallback<X509Certificate> securityCallback) {
        this.securityCallback.setTlsTmSecurityCallback(securityCallback);
    }

    public SSLEngineConfigurator getSslEngineConfigurator() {
        return sslEngineConfigurator;
    }

    /**
     * Sets the configurator for the {@link SSLEngine} internally used to run the TLS communication. This method should
     * be called before any new connection is established that should use this configurator/configuration.
     * @param sslEngineConfigurator
     *    a {@link SSLEngineConfigurator} instance like {@link DefaultSSLEngineConfiguration}.
     * @since 3.0.5
     */
    public void setSslEngineConfigurator(SSLEngineConfigurator sslEngineConfigurator) {
        this.sslEngineConfigurator = sslEngineConfigurator;
    }

    public TLSTMTrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    /**
     * Set the TLSTM trust manager factory. Using a trust manager factory other than the
     * default allows to add support for Java 1.7 X509ExtendedTrustManager.
     *
     * @param trustManagerFactory
     *         a X.509 trust manager factory implementing the interface {@link TLSTMTrustManagerFactory}.
     *
     * @since 2.0.3
     */
    public void setTrustManagerFactory(TLSTMTrustManagerFactory trustManagerFactory) {
        if (trustManagerFactory == null) {
            throw new NullPointerException();
        }
        this.trustManagerFactory = trustManagerFactory;
    }

    /**
     * Listen for incoming and outgoing requests. If the {@code serverEnabled}
     * member is {@code false} the server for incoming requests is not
     * started. This starts the internal server thread that processes messages.
     *
     * @throws java.net.SocketException
     *         when the transport is already listening for incoming/outgoing messages.
     * @throws java.io.IOException
     *         if the listen port could not be bound to the server thread.
     */
    public synchronized void listen() throws IOException {
        if (server != null) {
            throw new SocketException("Port already listening");
        }
        try {
            serverThread = new ServerThread();
            if (logger.isInfoEnabled()) {
                logger.info("TCP address " + tcpAddress + " bound successfully");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SSL not available: " + e.getMessage(), e);
        }
        server = SNMP4JSettings.getThreadFactory().createWorkerThread(
                "TLSTM_" + getListenAddress(), serverThread, true);
        if (connectionTimeout > 0) {
            // run as daemon
            socketCleaner = SNMP4JSettings.getTimerFactory().createTimer();
        }
        server.run();
    }

    /**
     * Sets the name of the listen thread for this UDP transport mapping.
     * This method has no effect, if called before {@link #listen()} has been
     * called for this transport mapping.
     *
     * @param name
     *         the new thread name.
     *
     * @since 1.6
     */
    public void setThreadName(String name) {
        WorkerTask st = server;
        if (st instanceof Thread) {
            ((Thread) st).setName(name);
        }
    }

    /**
     * Returns the name of the listen thread.
     *
     * @return the thread name if in listening mode, otherwise {@code null}.
     * @since 1.6
     */
    public String getThreadName() {
        WorkerTask st = server;
        if (st != null) {
            return ((Thread) st).getName();
        } else {
            return null;
        }
    }

    /**
     * Closes all open sockets and stops the internal server thread that
     * processes messages.
     */
    public void close() {
        for (SocketEntry entry : sockets.values()) {
            entry.closeSession();
        }
        WorkerTask st = server;
        server = null;
        if (st != null) {
            st.terminate();
            st.interrupt();
            try {
                st.join();
            } catch (InterruptedException ex) {
                logger.warn(ex);
            }
            closeSockets(sockets);
            if (socketCleaner != null) {
                socketCleaner.cancel();
            }
            socketCleaner = null;
        }
    }

    /**
     * Sends a SNMP message to the supplied address.
     *
     * @param address
     *         an {@code TcpAddress}. A {@code ClassCastException} is thrown
     *         if {@code address} is not a {@code TcpAddress} instance.
     * @param message
     *         byte[]
     *         the message to sent.
     * @param tmStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     *
     * @throws java.io.IOException
     *         if an IO exception occurs while trying to send the message.
     */
    public void sendMessage(TcpAddress address, byte[] message,
                            TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException {
        if (server == null || serverThread == null) {
            if (isOpenSocketOnSending()) {
                listen();
            }
            else {
                handleDroppedMessageToSend(address, message, tmStateReference, timeoutMillis, maxRetries);
            }
        }
        if (serverThread != null) {
            if ((suspendedAddresses.size() > 0) && suspendedAddresses.contains(address)) {
                handleDroppedMessageToSend(address, message, tmStateReference, timeoutMillis, maxRetries);
            }
            else {
                serverThread.sendMessage(address, message, tmStateReference);
            }
        }
    }

    /**
     * Gets the connection timeout. This timeout specifies the time a connection
     * may be idle before it is closed.
     *
     * @return long
     * the idle timeout in milliseconds.
     */
    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    /**
     * Sets the connection timeout. This timeout specifies the time a connection
     * may be idle before it is closed.
     *
     * @param connectionTimeout
     *         the idle timeout in milliseconds. A zero or negative value will disable
     *         any timeout and connections opened by this transport mapping will stay
     *         opened until they are explicitly closed.
     */
    public void setConnectionTimeout(long connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * Gets the {@link CommonTimer} that controls socket cleanup operations.
     *
     * @return a socket cleaner timer.
     * @since 3.0
     */
    @Override
    public CommonTimer getSocketCleaner() {
        return socketCleaner;
    }

    @Override
    public MessageLengthDecoder getMessageLengthDecoder() {
        return null;
    }

    @Override
    public void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder) {
/*
    if (messageLengthDecoder == null) {
      throw new NullPointerException();
    }
    this.messageLengthDecoder = messageLengthDecoder;
    */
    }

    /**
     * Gets the inbound buffer size for incoming requests. When SNMP packets are
     * received that are longer than this maximum size, the messages will be
     * silently dropped and the connection will be closed.
     *
     * @return the maximum inbound buffer size in bytes.
     */
    public int getMaxInboundMessageSize() {
        return super.getMaxInboundMessageSize();
    }

    /**
     * Sets the maximum buffer size for incoming requests. When SNMP packets are
     * received that are longer than this maximum size, the messages will be
     * silently dropped and the connection will be closed.
     *
     * @param maxInboundMessageSize
     *         the length of the inbound buffer in bytes.
     */
    public void setMaxInboundMessageSize(int maxInboundMessageSize) {
        this.maxInboundMessageSize = maxInboundMessageSize;
    }


    private synchronized void timeoutSocket(SocketEntry entry) {
        if (connectionTimeout > 0) {
            SocketTimeout<TcpAddress> socketTimeout = new SocketTimeout<>(this, entry);
            entry.setSocketTimeout(socketTimeout);
            socketCleaner.schedule(socketTimeout, connectionTimeout);
        }
    }

    public boolean isListening() {
        return (server != null);
    }

    protected TlsAddress createIncomingAddress(Socket s) {
        return new TlsAddress(s.getInetAddress(), s.getPort());
    }

    @Override
    public TcpAddress getListenAddress() {
        int port = tcpAddress.getPort();
        ServerThread serverThreadCopy = serverThread;
        try {
            port = serverThreadCopy.ssc.socket().getLocalPort();
        } catch (NullPointerException npe) {
            if (logger.isDebugEnabled()) {
                logger.debug("TLSTM.getListenAddress called but TLSTM is not listening yet");
            }
        }
        return new TlsAddress(tcpAddress.getInetAddress(), port);
    }



    class SocketEntry extends AbstractSocketEntry {
        private LinkedList<byte[]> message = new LinkedList<byte[]>();
        private ByteBuffer inNetBuffer;
        private ByteBuffer inAppBuffer;
        private ByteBuffer outAppBuffer;
        private ByteBuffer outNetBuffer;
        private SSLEngine sslEngine;
        private long sessionID;
        private TransportStateReference tmStateReference;
        private boolean handshakeFinished;

        private final Object outboundLock = new Object();
        private final Object inboundLock = new Object();

        public SocketEntry(TcpAddress address, Socket socket,
                           boolean useClientMode,
                           TransportStateReference tmStateReference) throws GeneralSecurityException {
            super(address, socket);
            this.inAppBuffer = ByteBuffer.allocate(getMaxInboundMessageSize());
            this.inNetBuffer = ByteBuffer.allocate(getMaxInboundMessageSize());
            this.outNetBuffer = ByteBuffer.allocate(getMaxInboundMessageSize());
            this.tmStateReference = tmStateReference;
            if (tmStateReference == null) {
                counterSupport.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionAccepts));
            }
            SSLEngineConfigurator sslEngineConfigurator = ensureSslEngineConfigurator();
            SSLContext sslContext = sslEngineConfigurator.getSSLContext(useClientMode, tmStateReference);
            this.sslEngine = sslContext.createSSLEngine(address.getInetAddress().getHostName(), address.getPort());
            sslEngine.setUseClientMode(useClientMode);
            sslEngineConfigurator.configure(sslEngine);
            synchronized (TLSTM.this) {
                sessionID = nextSessionID++;
            }
        }

        public synchronized void addMessage(byte[] message) {
            this.message.add(message);
        }

        public synchronized byte[] nextMessage() {
            if (this.message.size() > 0) {
                return this.message.removeFirst();
            }
            return null;
        }

        public synchronized boolean hasMessage() {
            return !this.message.isEmpty();
        }

        @Override
        public void setSocketTimeout(SocketTimeout<TcpAddress> socketTimeout) {

        }

        public void setInNetBuffer(ByteBuffer byteBuffer) {
            this.inNetBuffer = byteBuffer;
        }

        public ByteBuffer getInNetBuffer() {
            return inNetBuffer;
        }

        public ByteBuffer getOutNetBuffer() {
            return outNetBuffer;
        }

        public void setOutNetBuffer(ByteBuffer outNetBuffer) {
            this.outNetBuffer = outNetBuffer;
        }

        public String toString() {
            return "SocketEntry[peerAddress=" + getPeerAddress() +
                    ",socket=" + socket + ",lastUse=" + new Date(getLastUse() / SnmpConstants.MILLISECOND_TO_NANOSECOND) +
                    ",inNetBuffer=" + inNetBuffer +
                    ",inAppBuffer=" + inAppBuffer +
                    ",outAppBuffer=" + outAppBuffer +
                    ",outNetBuffer=" + outNetBuffer +
                    ",socketTimeout=" + getSocketTimeout() + "]";
        }

        public void checkTransportStateReference() {
            if (tmStateReference == null) {
                tmStateReference =
                        new TransportStateReference(TLSTM.this, getPeerAddress(), new OctetString(),
                                SecurityLevel.authPriv, SecurityLevel.authPriv,
                                true, sessionID);
                OctetString securityName = null;
                try {
                    securityName = securityCallback.getSecurityName(
                            (X509Certificate[]) sslEngine.getSession().getPeerCertificates());
                } catch (SSLPeerUnverifiedException e) {
                    logger.error("SSL peer '" + getPeerAddress() + "' is not verified: " + e.getMessage(), e);
                    sslEngine.setEnableSessionCreation(false);
                }
                tmStateReference.setSecurityName(securityName);
            } else if (tmStateReference.getTransportSecurityLevel().equals(SecurityLevel.undefined)) {
                tmStateReference.setTransportSecurityLevel(SecurityLevel.authPriv);
            }
        }

        public void setInAppBuffer(ByteBuffer inAppBuffer) {
            this.inAppBuffer = inAppBuffer;
        }

        public ByteBuffer getInAppBuffer() {
            return inAppBuffer;
        }

        public boolean isHandshakeFinished() {
            return handshakeFinished;
        }

        public void setHandshakeFinished(boolean handshakeFinished) {
            this.handshakeFinished = handshakeFinished;
        }

        public boolean isAppOutPending() {
            synchronized (outboundLock) {
                return (outAppBuffer != null) && (outAppBuffer.limit() > 0);
            }
        }

        public long getSessionID() {
            return sessionID;
        }

        public void closeSession() {
            try {
                SSLEngineResult result;
                do {
                    result = sendNetMessage(this);
                }
                while (result != null && (result.getStatus() != SSLEngineResult.Status.CLOSED) &&
                        (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP));

            } catch (IOException e) {
                if (logger.isDebugEnabled()) {
                    logger.debug("IOException while closing outbound channel of " + this + ": " + e.getMessage());
                }
            }
            sslEngine.closeOutbound();
            counterSupport.fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpTlstmSessionServerCloses));
        }
    }

    /**
     * Returns the configured {@link #setSslEngineConfigurator(SSLEngineConfigurator)} or the
     * {@link DefaultSSLEngineConfiguration} which will then become the configured SSL engine configurator. This method
     * is not synchronized against concurrent execution of {@link #setSslEngineConfigurator(SSLEngineConfigurator)}.
     * @return
     *    a non-null {@link SSLEngineConfigurator}.
     * @since 3.0.5
     */
    protected SSLEngineConfigurator ensureSslEngineConfigurator() {
        if (sslEngineConfigurator == null) {
            sslEngineConfigurator =
                    new DefaultSSLEngineConfiguration(this, trustManagerFactory, DEFAULT_TLSTM_PROTOCOLS);
        }
        return sslEngineConfigurator;
    }

    class ServerThread extends AbstractTcpServerThread<SocketEntry> {

        private Throwable lastError = null;
        private ServerSocketChannel ssc;

        private BlockingQueue<SocketEntry> outQueue = new LinkedBlockingQueue<SocketEntry>();
        private BlockingQueue<SocketEntry> inQueue = new LinkedBlockingQueue<SocketEntry>();

        public ServerThread() throws IOException, NoSuchAlgorithmException {
            super(TLSTM.this);
            // Selector for incoming requests
            if (serverEnabled) {
                // Create a new server socket and set to non blocking mode
                ssc = ServerSocketChannel.open();
                ssc.configureBlocking(false);

                // Bind the server socket
                InetSocketAddress isa = new InetSocketAddress(tcpAddress.getInetAddress(), tcpAddress.getPort());
                setSocketOptions(ssc.socket());
                ssc.socket().bind(isa);
                // Register accepts on the server socket with the selector. This
                // step tells the selector that the socket wants to be put on the
                // ready list when accept operations occur, so allowing multiplexed
                // non-blocking I/O to take place.
                ssc.register(selector, SelectionKey.OP_ACCEPT);
            }
        }

        private synchronized void processQueues() {
            while (!outQueue.isEmpty() || !inQueue.isEmpty()) {
                while (!outQueue.isEmpty()) {
                    SocketEntry entry = null;
                    try {
                        SSLEngineResult result;
                        entry = outQueue.take();
                        result = sendNetMessage(entry);
                        if (result != null && runDelegatedTasks(result, entry)) {
//                        if (result == null || runDelegatedTasks(result, entry)) {
                            if (entry.isAppOutPending()) {
                                writeMessage(entry, entry.getSocket().getChannel());
                            }
                        }
                     } catch (IOException iox) {
                        logger.error("IO exception caught while SSL processing: " + iox.getMessage(), iox);
                        while (inQueue.remove(entry)) {
                            // no body
                        }
                    } catch (InterruptedException e) {
                        logger.error("SSL processing interrupted: " + e.getMessage(), e);
                        return;
                    }
                }
                while (!inQueue.isEmpty()) {
                    SocketEntry entry = null;
                    try {
                        entry = inQueue.take();
                        synchronized (entry.inboundLock) {
                            // Is there any data to read?
                            if (entry.getInNetBuffer().position() > 0) {
                                entry.inNetBuffer.flip();
                                if (logger.isDebugEnabled()) {
                                    logger.debug("TLS inNetBuffer = " + entry.inNetBuffer);
                                }
                                SSLEngineResult nextResult =
                                        entry.sslEngine.unwrap(entry.inNetBuffer, entry.inAppBuffer);
                                adjustInNetBuffer(entry, nextResult);
                                if (runDelegatedTasks(nextResult, entry)) {
                                    switch (nextResult.getStatus()) {
                                        case BUFFER_UNDERFLOW:
                                            entry.inNetBuffer.position(entry.inNetBuffer.limit());
                                            entry.inNetBuffer.limit(entry.inNetBuffer.capacity());
                                            entry.addRegistration(selector, SelectionKey.OP_READ);
                                            break;
                                        case BUFFER_OVERFLOW:
                                            // TODO
                                            break;
                                        case CLOSED:
                                            continue;
                                        case OK:
                                            if (entry.isAppOutPending()) {
                                                // we have a message to send
                                                writeMessage(entry, entry.getSocket().getChannel());
                                            }
                                            entry.inAppBuffer.flip();
                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Dispatching inAppBuffer=" + entry.inAppBuffer);
                                            }
                                            if (entry.inAppBuffer.limit() > 0) {
                                                dispatchMessage(entry.getPeerAddress(),
                                                        entry.inAppBuffer, entry.inAppBuffer.limit(),
                                                        entry.sessionID, entry.tmStateReference);
                                            }
                                            entry.inAppBuffer.clear();
                                    }
                                }
                            }
                            else {
                                entry.addRegistration(selector, SelectionKey.OP_READ);
                            }
                        }
                    } catch (IOException iox) {
                        logger.error("IO exception caught while SSL processing: " + iox.getMessage(), iox);
                        while (inQueue.remove(entry)) {
                            // no body
                        }
                    } catch (InterruptedException e) {
                        logger.error("SSL processing interrupted: " + e.getMessage(), e);
                        return;
                    }
                }
            }
        }

        private void processPending() {
            synchronized (pending) {
                for (int i = 0; i < pending.size(); i++) {
                    SocketEntry entry = pending.getFirst();
                    try {
                        // Register the channel with the selector, indicating
                        // interest in connection completion and attaching the
                        // target object so that we can get the target back
                        // after the key is added to the selector's
                        // selected-key set
                        if (entry.getSocket().isConnected()) {
                            if (entry.isHandshakeFinished()) {
                                entry.addRegistration(selector, SelectionKey.OP_WRITE);
                            }
                        } else {
                            entry.addRegistration(selector, SelectionKey.OP_CONNECT);
                        }
                    } catch (CancelledKeyException ckex) {
                        logger.warn(ckex);
                        pending.remove(entry);
                        try {
                            entry.getSocket().getChannel().close();
                            TransportStateEvent e =
                                    new TransportStateEvent(TLSTM.this,
                                            entry.getPeerAddress(),
                                            TransportStateEvent.STATE_CLOSED,
                                            null);
                            fireConnectionStateChanged(e);
                        } catch (IOException ex) {
                            logger.error(ex);
                        }
                    } catch (IOException iox) {
                        logger.error(iox);
                        pending.remove(entry);
                        // Something went wrong, so close the channel and
                        // record the failure
                        try {
                            entry.getSocket().getChannel().close();
                            TransportStateEvent e =
                                    new TransportStateEvent(TLSTM.this,
                                            entry.getPeerAddress(),
                                            TransportStateEvent.STATE_CLOSED,
                                            iox);
                            fireConnectionStateChanged(e);
                        } catch (IOException ex) {
                            logger.error(ex);
                        }
                        lastError = iox;
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(iox);
                        }
                    }
                }
            }
        }

        /**
         * If the result indicates that we have outstanding tasks to do,
         * go ahead and run them in this thread.
         *
         * @param result
         *         the SSLEngine wrap/unwrap result.
         * @param entry
         *         the session to use.
         *
         * @return {@code true} if processing of delegated tasks has been
         * finished, {@code false} otherwise.
         */
        public boolean runDelegatedTasks(SSLEngineResult result,
                                         SocketEntry entry) throws IOException {
            if (logger.isDebugEnabled()) {
                logger.debug("Running delegated task on " + entry + ": " + result);
            }
            SSLEngineResult.HandshakeStatus status = result.getHandshakeStatus();
            if (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable runnable;
                while ((runnable = entry.sslEngine.getDelegatedTask()) != null) {
                    logger.debug("Running delegated task...");
                    runnable.run();
                }
                status = entry.sslEngine.getHandshakeStatus();
                if (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    throw new IOException("Inconsistent Handshake status");
                }
                logger.info("Handshake status = " + status);
            }
            switch (result.getStatus()) {
                case BUFFER_UNDERFLOW:
                    entry.inNetBuffer.position(entry.inNetBuffer.limit());
                    entry.inNetBuffer.limit(entry.inNetBuffer.capacity());
                    entry.addRegistration(selector, SelectionKey.OP_READ);
                    return false;
                case CLOSED:
                    return false;
            }
            switch (status) {
                case NEED_WRAP:
                    outQueue.add(entry);
                    break;
                case NEED_UNWRAP:
                    if (logger.isDebugEnabled()) {
                        logger.debug("NEED_UNWRAP processing with inNetBuffer=" + entry.inNetBuffer);
                    }
                    inQueue.add(entry);
                    entry.addRegistration(selector, SelectionKey.OP_READ);
                    break;
                case FINISHED:
                    logger.debug("TLS handshake finished");
                    // register for post handshake data (TLS 1.3)
                    entry.addRegistration(selector, SelectionKey.OP_READ);
                    entry.setHandshakeFinished(true);
                    // fall through
                case NOT_HANDSHAKING:
                    if (result.bytesProduced() > 0) {
                        writeNetBuffer(entry, entry.getSocket().getChannel());
                    }
                    return true;
            }
            return false;
        }

        public Throwable getLastError() {
            return lastError;
        }

        public void sendMessage(Address address, byte[] message, TransportStateReference tmStateReference)
                throws IOException {
            Socket s = null;
            SocketEntry entry = sockets.get(address);
            if (logger.isDebugEnabled()) {
                logger.debug("Looking up connection for destination '" + address +
                        "' returned: " + entry);
                logger.debug(sockets.toString());
            }
            if (entry != null) {
                if ((tmStateReference != null) && (tmStateReference.getSessionID() != null) &&
                        (!tmStateReference.getSessionID().equals(entry.getSessionID()))) {
                    // session IDs do not match -> drop message
                    counterSupport.fireIncrementCounter(
                            new CounterEvent(this, SnmpConstants.snmpTlstmSessionInvalidCaches));
                    String errmsg = "Session " + tmStateReference.getSessionID() + " not available";
                    if (logger.isDebugEnabled()) {
                        logger.debug(errmsg);
                    }
                    throw new IOException(errmsg);
                }
                s = entry.getSocket();
            }
            if ((s == null) || (s.isClosed()) || (!s.isConnected())) {
                if (tmStateReference != null && tmStateReference.isSameSecurity()) {
                    // session IDs do not match -> drop message
                    counterSupport.fireIncrementCounter(
                            new CounterEvent(this, SnmpConstants.snmpTlstmSessionNoSessions));
                    throw new IOException("Session " + tmStateReference.getSessionID() + " not available");
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("Socket for address '" + address + "' is closed, opening it...");
                }
                synchronized (pending) {
                    pending.remove(entry);
                }
                SocketChannel sc;
                try {
                    InetSocketAddress targetAddress = new InetSocketAddress(((TcpAddress) address).getInetAddress(),
                                    ((TcpAddress) address).getPort());
                    if ((s == null) || (s.isClosed())) {
                        // Open the channel, set it to non-blocking, initiate connect
                        sc = SocketChannel.open();
                        sc.configureBlocking(false);
                        sc.connect(targetAddress);
                        counterSupport.fireIncrementCounter(
                                new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpens));
                    } else {
                        sc = s.getChannel();
                        sc.configureBlocking(false);
                        if (!sc.isConnectionPending()) {
                            sc.connect(targetAddress);
                            counterSupport.fireIncrementCounter(
                                    new CounterEvent(this, SnmpConstants.snmpTlstmSessionOpens));
                        } else {
                            if (matchingStateReferences(tmStateReference, entry.tmStateReference)) {
                                entry.addMessage(message);
                                synchronized (pending) {
                                    pending.add(entry);
                                }
                                selector.wakeup();
                                return;
                            } else {
                                logger.error("TransportStateReferences refNew=" + tmStateReference +
                                        ",refOld=" + entry.tmStateReference + " do not match, message dropped");
                                throw new IOException("Transport state reference does not match existing reference" +
                                        " for this session/target");
                            }
                        }
                    }
                    s = sc.socket();
                    try {
                        entry = new SocketEntry((TcpAddress) address, s, true, tmStateReference);
                    }
                    catch (GeneralSecurityException gse) {
                        throw new IOException("Security exception while sending message to " + address +
                                ": " + gse.getMessage(), gse);
                    }
                    entry.addMessage(message);
                    connectSocketToSendMessage(address, message, s, entry, sockets);
                } catch (IOException iox) {
                    logger.error(iox);
                    throw iox;
                }
            } else if (matchingStateReferences(tmStateReference, entry.tmStateReference)) {
                entry.addMessage(message);
                synchronized (pending) {
                    pending.addFirst(entry);
                }
                logger.debug("Waking up selector for new message");
                selector.wakeup();
            } else {
                logger.error("TransportStateReferences refNew=" + tmStateReference +
                        ",refOld=" + entry.tmStateReference + " do not match, message dropped");
                throw new IOException("Transport state reference does not match existing reference" +
                        " for this session/target");

            }
        }


        @Override
        public void run() {
            // Here's where everything happens. The select method will
            // return when any operations registered above have occurred, the
            // thread has been interrupted, etc.
            try {
                while (!stop) {
                    try {
                        processQueues();
                        if (selector.select() > 0) {
                            if (stop) {
                                break;
                            }
                            // Someone is ready for I/O, get the ready keys
                            Set<SelectionKey> readyKeys = selector.selectedKeys();
                            Iterator<SelectionKey> it = readyKeys.iterator();

                            // Walk through the ready keys collection and process date requests.
                            while (it.hasNext()) {
                                try {
                                    SocketEntry entry = null;
                                    SelectionKey sk = it.next();
                                    it.remove();
                                    SocketChannel readChannel = null;
                                    TcpAddress incomingAddress = null;
                                    if (sk.isAcceptable()) {
                                        logger.debug("Key is acceptable");
                                        // The key indexes into the selector so you
                                        // can retrieve the socket that's ready for I/O
                                        ServerSocketChannel nextReady =
                                                (ServerSocketChannel) sk.channel();
                                        Socket s = nextReady.accept().socket();
                                        readChannel = s.getChannel();
                                        readChannel.configureBlocking(false);

                                        incomingAddress = new TlsAddress(s.getInetAddress(), s.getPort());
                                        try {
                                            entry = new SocketEntry(incomingAddress, s, false, null);
                                        }
                                        catch (GeneralSecurityException gse) {
                                            logger.error("Failed to accept incoming connection from "+incomingAddress+
                                                    " because of a security exception: "+gse.getMessage(), gse);
                                            s.close();
                                            continue;
                                        }
                                        entry.addRegistration(selector, SelectionKey.OP_READ);
                                        sockets.put(incomingAddress, entry);
                                        timeoutSocket(entry);
                                        TransportStateEvent e =
                                                new TransportStateEvent(TLSTM.this,
                                                        incomingAddress,
                                                        TransportStateEvent.STATE_CONNECTED,
                                                        null);
                                        fireConnectionStateChanged(e);
                                        if (e.isCancelled()) {
                                            logger.warn("Incoming connection cancelled");
                                            s.close();
                                            removeSocketEntry(incomingAddress);
                                            readChannel = null;
                                        }
                                    } else if (sk.isWritable()) {
                                        logger.debug("Key is writable");
                                        incomingAddress = writeData(sk, incomingAddress);
                                    } else if (sk.isReadable()) {
                                        logger.debug("Key is readable");
                                        readChannel = (SocketChannel) sk.channel();
                                        incomingAddress = createIncomingAddress(readChannel.socket());
                                    } else if (sk.isConnectable()) {
                                        logger.debug("Key is connectable");
                                        connectChannel(sk, incomingAddress);
                                    }

                                    if (readChannel != null) {
                                        logger.debug("Key is reading");
                                        try {
                                            readMessage(sk, readChannel, incomingAddress, entry);
                                        } catch (IOException iox) {
                                            // IO exception -> channel closed remotely
                                            logger.warn(iox);
                                            cancelNonServerSelectionKey(sk);
                                            readChannel.close();
                                            counterSupport.fireIncrementCounter(
                                                    new CounterEvent(this,
                                                            isServerEnabled() ?
                                                                    SnmpConstants.snmpTlstmSessionClientCloses :
                                                                    SnmpConstants.snmpTlstmSessionServerCloses));
                                            removeSocketEntry(incomingAddress);
                                            TransportStateEvent e =
                                                    new TransportStateEvent(TLSTM.this, incomingAddress,
                                                            TransportStateEvent.STATE_DISCONNECTED_REMOTELY,
                                                            iox);
                                            fireConnectionStateChanged(e);
                                        }
                                    }
                                } catch (CancelledKeyException ckex) {
                                    if (logger.isDebugEnabled()) {
                                        logger.debug("Selection key cancelled, skipping it");
                                    }
                                 }
                            }
                        }
                    } catch (NullPointerException npex) {
                        // There seems to happen a NullPointerException within the select()
                        npex.printStackTrace();
                        logger.warn("NullPointerException within select()?");
                        stop = true;
                    }
                    if (!stop) {
                        processPending();
                    }
                }
                if (ssc != null) {
                    ssc.close();
                }
                if (selector != null) {
                    selector.close();
                }
            } catch (IOException iox) {
                logger.error(iox);
                lastError = iox;
            }
            if (!stop) {
                stop = true;
                synchronized (TLSTM.this) {
                    server = null;
                }
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Worker task finished: " + getClass().getName());
            }
        }

        @Override
        public SocketEntry removeSocketEntry(TcpAddress incomingAddress) {
            return sockets.remove(incomingAddress);
        }

        @Override
        protected TcpAddress writeData(SelectionKey sk, TcpAddress incomingAddress) {
            SocketEntry entry = (SocketEntry) sk.attachment();
            try {
                SocketChannel sc = (SocketChannel) sk.channel();
                incomingAddress =createIncomingAddress(sc.socket());
                if ((entry != null) && (!entry.hasMessage())) {
                    synchronized (pending) {
                        pending.remove(entry);
                        entry.removeRegistration(selector, SelectionKey.OP_WRITE);
                    }
                }
                if (entry != null) {
                    writeMessage(entry, sc);
                }
            }
            catch (IOException iox) {
                logger.warn(iox);
                // make sure channel is closed properly:
                closeChannel(sk.channel());
                removeSocketEntry(incomingAddress);
                TransportStateEvent e =
                        new TransportStateEvent(TLSTM.this, incomingAddress,
                                TransportStateEvent.STATE_DISCONNECTED_REMOTELY, iox);
                fireConnectionStateChanged(e);
             }
            return incomingAddress;
        }

        private void readMessage(SelectionKey sk, SocketChannel readChannel, TcpAddress incomingAddress,
                                 SocketEntry session) throws IOException {
            SocketEntry entry = (SocketEntry) sk.attachment();
            if (entry == null) {
                entry = session;
            }
            if (entry == null) {
                logger.error("SocketEntry null in readMessage");
            }
            assert (entry != null);
            // note that socket has been used
            entry.used();
            ByteBuffer inNetBuffer = entry.getInNetBuffer();
            ByteBuffer inAppBuffer = entry.getInAppBuffer();
            try {
                long bytesRead = readChannel.read(inNetBuffer);
                if (logger.isDebugEnabled()) {
                    logger.debug("Read " + bytesRead + " bytes from " + incomingAddress);
                    logger.debug("TLS inNetBuffer: " + inNetBuffer);
                }
                if (bytesRead < 0) {
                    logger.debug("Socket closed remotely");
                    cancelNonServerSelectionKey(sk);
                    readChannel.close();
                    TransportStateEvent e =
                            new TransportStateEvent(TLSTM.this, incomingAddress,
                                    TransportStateEvent.STATE_DISCONNECTED_REMOTELY, null);
                    fireConnectionStateChanged(e);
                    return;
                }
                if (bytesRead > 0) {
                    SSLEngineResult result;
                    synchronized (entry.inboundLock) {
                        do {
                            inNetBuffer.flip();
                            result = entry.sslEngine.unwrap(inNetBuffer, inAppBuffer);
                            adjustInNetBuffer(entry, result);
                            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                                logger.error("BUFFER_OVERFLOW");
                                throw new IOException("BUFFER_OVERFLOW");
                            }
                            if (runDelegatedTasks(result, entry)) {
                                if (result.bytesProduced() > 0) {
                                    entry.inAppBuffer.flip();
                                    // check for 16K fragment overflow which requires reassembling on
                                    // SNMP application level
                                    if (entry.inAppBuffer.remaining() % tlsMaxFragmentSize == 0) {
                                        if (logger.isDebugEnabled()) {
                                            logger.debug("Checking PDU header for fragmented message: " + entry);
                                        }
                                        try {
                                            BER.decodeHeader(new BERInputStream(entry.inAppBuffer.asReadOnlyBuffer()),
                                                    new BER.MutableByte(), true);
                                        } catch (IOException iox) {
                                            entry.inAppBuffer.position(entry.inAppBuffer.limit());
                                            entry.inAppBuffer.limit(entry.inAppBuffer.capacity());
                                            // wait to get rest of the PDU first
                                            if (logger.isDebugEnabled()) {
                                                logger.debug("Waiting for rest of packet because: " + iox.getMessage() +
                                                        ", inAppBuffer=" + entry.inAppBuffer);
                                            }
                                            continue;
                                        }
                                    }
                                    entry.checkTransportStateReference();
                                    dispatchMessage(incomingAddress, inAppBuffer, inAppBuffer.limit(), entry.sessionID,
                                            entry.tmStateReference);
                                    entry.getInAppBuffer().clear();
                                    break;
                                } else if (entry.isAppOutPending()) {
                                    writeMessage(entry, entry.getSocket().getChannel());
                                }
                            }
                            else {
                                break;
                            }
                        } while (inNetBuffer.position() > 0 && inNetBuffer.remaining() > 0);
                    }
                }
            } catch (ClosedChannelException ccex) {
                cancelNonServerSelectionKey(sk);
                if (logger.isDebugEnabled()) {
                    logger.debug("Read channel not open, no bytes read from " +
                            incomingAddress);
                }
            }
        }

        private void dispatchMessage(TcpAddress incomingAddress,
                                     ByteBuffer byteBuffer, long bytesRead,
                                     Object sessionID,
                                     TransportStateReference tmStateReference) {
            byteBuffer.flip();
            if (logger.isDebugEnabled()) {
                logger.debug("Received message from " + incomingAddress + " with length " + bytesRead + ": " +
                        new OctetString(byteBuffer.array(), 0,
                                (int) bytesRead).toHexString());
            }
            ByteBuffer bis;
            if (isAsyncMsgProcessingSupported()) {
                byte[] bytes = new byte[(int) bytesRead];
                System.arraycopy(byteBuffer.array(), 0, bytes, 0, (int) bytesRead);
                bis = ByteBuffer.wrap(bytes);
            } else {
                bis = ByteBuffer.wrap(byteBuffer.array(),
                        0, (int) bytesRead);
            }
            fireProcessMessage(incomingAddress, bis, tmStateReference);
        }

        private void writeMessage(SocketEntry entry, SocketChannel sc) throws IOException {
            synchronized (entry.outboundLock) {
                boolean sendNextFragment = false;
                do {
                    sendNextFragment = false;
                    int offset = 0;
                    if (entry.outAppBuffer == null) {
                        byte[] message = entry.nextMessage();
                        if (message != null) {
                            entry.outAppBuffer = ByteBuffer.wrap(message);
                            if (logger.isDebugEnabled()) {
                                logger.debug("Sending message with length " +
                                        message.length + " as "+
                                        (entry.sslEngine.getUseClientMode() ? "client":"server") + " to " +
                                        entry.getPeerAddress() + ": " +
                                        new OctetString(message).toHexString());
                            }
                        } else {
                            entry.removeRegistration(selector, SelectionKey.OP_WRITE);
                            // Make sure that we did not clear a selection key that was concurrently
                            // added:
                            if (entry.hasMessage() && !entry.isRegistered(SelectionKey.OP_WRITE)) {
                                entry.addRegistration(selector, SelectionKey.OP_WRITE);
                                logger.debug("Waking up selector");
                                selector.wakeup();
                            }
                            entry.addRegistration(selector, SelectionKey.OP_READ);
                            return;
                        }
                    }
                    else {
                        offset = entry.outAppBuffer.position();
                    }
                    SSLEngineResult result;
                    result = entry.sslEngine.wrap(entry.outAppBuffer, entry.outNetBuffer);
                    if (result.getStatus() == SSLEngineResult.Status.OK) {
                        if (result.bytesProduced() > 0) {
                            writeNetBuffer(entry, sc);
                        }
                        else if (logger.isDebugEnabled()) {
                            logger.debug("SSL Engine status of wrap is ok, but 0 NET bytes produced");
                        }
                    } else if (runDelegatedTasks(result, entry)) {
                        logger.debug("SSL session OK");
                    }
                    if (result.bytesConsumed() >= entry.outAppBuffer.limit() - offset) {
                        logger.debug("Payload sent completely");
                        entry.outAppBuffer = null;
                    } else if (result.bytesConsumed() > 0) {
                        logger.debug("Fragment of size " + result.bytesConsumed() + " sent: " + entry);
                        sendNextFragment = true;
                    }
                } while (sendNextFragment);
                if (logger.isDebugEnabled()) {
                    logger.debug("Message sent for "+entry);
                }
            }
            entry.addRegistration(selector, SelectionKey.OP_READ);
        }
    }

    void writeNetBuffer(SocketEntry entry, SocketChannel sc) throws IOException {
        entry.outNetBuffer.flip();
        // Send SSL/TLS encoded data to peer
        while (entry.outNetBuffer.hasRemaining()) {
            logger.debug("Writing TLS outNetBuffer(PAYLOAD): " + entry.outNetBuffer);
            int num = sc.write(entry.outNetBuffer);
            logger.debug("Wrote TLS " + num + " bytes from outNetBuffer(PAYLOAD)");
            if (num == -1) {
                throw new IOException("TLS connection closed");
            } else if (num == 0) {
                entry.outNetBuffer.compact();
                return;
            }
        }
        entry.outNetBuffer.clear();
    }

    private boolean matchingStateReferences(TransportStateReference tmStateReferenceNew,
                                            TransportStateReference tmStateReferenceExisting) {
        if (tmStateReferenceNew.getSecurityName() == null && tmStateReferenceExisting.getSecurityName() == null) {
            return true;
        }
        else if (tmStateReferenceExisting == null) {
            logger.error("Failed to compare TransportStateReferences refNew=" + tmStateReferenceNew +
                    ",refOld=" + tmStateReferenceExisting);
            return false;
        }
        if ((tmStateReferenceNew.getSecurityName() == null) || (tmStateReferenceExisting.getSecurityName() == null)) {
            logger.error("Could not match TransportStateReferences refNew=" + tmStateReferenceNew +
                    ",refOld=" + tmStateReferenceExisting);
            return false;
        } else return tmStateReferenceNew.getSecurityName().equals(tmStateReferenceExisting.getSecurityName());
    }

    private SSLEngineResult sendNetMessage(SocketEntry entry) throws IOException {
        SSLEngineResult result;
        synchronized (entry.outboundLock) {
            if (!entry.outNetBuffer.hasRemaining()) {
                return null;
            }
            result = entry.sslEngine.wrap(ByteBuffer.allocate(0), entry.outNetBuffer);
            entry.outNetBuffer.flip();
            logger.debug("TLS outNetBuffer = " + entry.outNetBuffer);
            entry.socket.getChannel().write(entry.outNetBuffer);
            entry.outNetBuffer.clear();
        }
        return result;
    }

    private void adjustInNetBuffer(SocketEntry entry, SSLEngineResult result) {
        if (result.getStatus() == SSLEngineResult.Status.OK) {
            if (result.bytesConsumed() == entry.inNetBuffer.limit()) {
                entry.inNetBuffer.clear();
            } else if (result.bytesConsumed() > 0) {
                entry.inNetBuffer.compact();
            }
        }
    }

    private class DefaultTLSTMTrustManagerFactory implements TLSTMTrustManagerFactory {
        public X509TrustManager create(X509TrustManager trustManager, boolean useClientMode,
                                       TransportStateReference tmStateReference) {
            return new TlsTrustManager(trustManager, useClientMode, tmStateReference, counterSupport, securityCallback);
        }
    }
}
