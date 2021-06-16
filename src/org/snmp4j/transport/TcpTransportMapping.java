/*_############################################################################
  _## 
  _##  SNMP4J - TcpTransportMapping.java  
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

import java.io.IOException;

import org.snmp4j.SNMP4JSettings;
import org.snmp4j.TransportStateReference;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.util.CommonTimer;
import org.snmp4j.util.WorkerTask;

/**
 * The {@code TcpTransportMapping} is the abstract base class for
 * TCP transport mappings.
 * @param <S> defines the type of {@link AbstractSocketEntry} used by this transport mapping.
 *
 * @author Frank Fock
 * @version 3.4.4
 */
public abstract class TcpTransportMapping<S extends AbstractSocketEntry>
        extends AbstractTransportMapping<TcpAddress>
        implements ConnectionOrientedTransportMapping<TcpAddress> {

    private static final LogAdapter logger = LogFactory.getLogger(TcpTransportMapping.class);

    protected TcpAddress tcpAddress;
    protected Map<Address, S> sockets = new ConcurrentHashMap<>();
    // 1 minute default timeout
    protected long connectionTimeout = 60000;
    protected CommonTimer socketCleaner;
    protected WorkerTask server;
    protected boolean serverEnabled = false;
    private transient List<TransportStateListener> transportStateListeners;
    /**
     * Enable or disable automatic (re)opening the communication socket when sending a message
     */
    protected boolean openSocketOnSending = true;

    public TcpTransportMapping(TcpAddress tcpAddress) {
        this.tcpAddress = tcpAddress;
    }

    public Class<? extends Address> getSupportedAddressClass() {
        return TcpAddress.class;
    }

    /**
     * Returns the transport address that is used by this transport mapping for
     * sending and receiving messages.
     *
     * @return the {@code Address} used by this transport mapping. The returned
     * instance must not be modified!
     */
    public TcpAddress getAddress() {
        return tcpAddress;
    }

    protected synchronized void timeoutSocket(AbstractServerSocket<TcpAddress> entry) {
        if ((connectionTimeout > 0) && (socketCleaner != null)) {
            SocketTimeout<TcpAddress> socketTimeout = new SocketTimeout<>(this, entry);
            entry.setSocketTimeout(socketTimeout);
            socketCleaner.schedule(socketTimeout, connectionTimeout);
        }
    }

    public TcpAddress getListenAddress() {
        return tcpAddress;
    }

    protected void closeSockets(Map<Address, S> sockets) {
        for (S entry : sockets.values()) {
            Socket s = entry.getSocket();
            if (s != null) {
                try {
                    SocketChannel sc = s.getChannel();
                    s.close();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Socket to " + entry.getPeerAddress() + " closed");
                    }
                    if (sc != null) {
                        sc.close();
                        if (logger.isDebugEnabled()) {
                            logger.debug("Socket channel to " + entry.getPeerAddress() + " closed");
                        }
                    }
                } catch (IOException iox) {
                    // ignore
                    logger.debug(iox);
                }
            }
        }
    }

    /**
     * Closes a connection to the supplied remote address, if it is open. This
     * method is particularly useful when not using a timeout for remote
     * connections.
     *
     * @param remoteAddress
     *         the address of the peer socket.
     *
     * @return {@code true} if the connection has been closed and
     * {@code false} if there was nothing to close.
     * @throws IOException
     *         if the remote address cannot be closed due to an IO exception.
     * @since 1.7.1
     */
    public synchronized boolean close(TcpAddress remoteAddress) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Closing socket for peer address " + remoteAddress);
        }
        AbstractSocketEntry entry = sockets.remove(remoteAddress);
        if (entry != null) {
            if (entry.getSocketTimeout() != null) {
                entry.getSocketTimeout().cancel();
            }
            Socket s = entry.getSocket();
            if (s != null) {
                SocketChannel sc = entry.getSocket().getChannel();
                entry.getSocket().close();
                if (logger.isInfoEnabled()) {
                    logger.info("Socket to " + entry.getPeerAddress() + " closed");
                }
                if (sc != null) {
                    sc.close();
                    if (logger.isDebugEnabled()) {
                        logger.debug("Closed socket channel for peer address " + remoteAddress);
                    }
                }
            }
            return true;
        }
        return false;
    }

    public abstract void sendMessage(TcpAddress address, byte[] message,
                                     TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException;

    /**
     * If {@code true} and method {@link #listen()} has not been called yet or the connection has been closed or reset,
     * then {@link #listen()} will be called to open the communication socket when a message is being sent using
     * {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)}.
     *
     * @return
     *     {@code true} if {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} will ensure that
     *     a server socket is there for receiving responses, {@code false} otherwise.
     * @since 3.4.4
     */
    public boolean isOpenSocketOnSending() {
        return openSocketOnSending;
    }

    /**
     * Activate or deactivate auto {@link #listen()} when
     * {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} is called but there is no listening
     * socket.
     *
     * @param openSocketOnSending
     *     {@code true} if {@link #sendMessage(TcpAddress, byte[], TransportStateReference, long, int)} should ensure
     *     that server socket is available for communication, {@code false} if {@link #listen()} must be called
     *     explicitly.
     * @since 3.4.4
     */
    public void setOpenSocketOnSending(boolean openSocketOnSending) {
        this.openSocketOnSending = openSocketOnSending;
    }

    public abstract void listen() throws IOException;

    public abstract void close() throws IOException;

    @Override
    public boolean isServerEnabled() {
        return serverEnabled;
    }

    /**
     * Returns the {@code MessageLengthDecoder} used by this transport
     * mapping.
     *
     * @return a MessageLengthDecoder instance.
     * @since 1.7
     */
    public abstract MessageLengthDecoder getMessageLengthDecoder();

    @Override
    public void setServerEnabled(boolean serverEnabled) {
        this.serverEnabled = serverEnabled;
    }

    /**
     * Sets the {@code MessageLengthDecoder} that decodes the total
     * message length from the header of a message.
     *
     * @param messageLengthDecoder
     *         a MessageLengthDecoder instance.
     *
     * @since 1.7
     */
    public abstract void setMessageLengthDecoder(MessageLengthDecoder messageLengthDecoder);

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

    public synchronized void addTransportStateListener(TransportStateListener l) {
        if (transportStateListeners == null) {
            transportStateListeners = new ArrayList<>(2);
        }
        transportStateListeners.add(l);
    }

    public synchronized void removeTransportStateListener(TransportStateListener l) {
        if (transportStateListeners != null) {
            transportStateListeners.remove(l);
        }
    }


    protected void fireConnectionStateChanged(TransportStateEvent change) {
        if (logger.isDebugEnabled()) {
            logger.debug("Firing transport state event: " + change);
        }
        final List<TransportStateListener> listenersFinalRef = transportStateListeners;
        if (listenersFinalRef != null) {
            try {
                List<TransportStateListener> listeners;
                synchronized (listenersFinalRef) {
                    listeners = new ArrayList<TransportStateListener>(listenersFinalRef);
                }
                for (TransportStateListener listener : listeners) {
                    listener.connectionStateChanged(change);
                }
            } catch (RuntimeException ex) {
                logger.error("Exception in fireConnectionStateChanged: " + ex.getMessage(), ex);
                if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                    throw ex;
                }
            }
        }
    }

    /**
     * Sets optional server socket options. The default implementation does
     * nothing.
     *
     * @param serverSocket
     *         the {@link ServerSocket} to apply additional non-default options.
     */
    protected void setSocketOptions(ServerSocket serverSocket) {
    }

    public WorkerTask getServer() {
        return server;
    }

    protected void cancelNonServerSelectionKey(SelectionKey sk) {
        if (!sk.isAcceptable()) {
            sk.cancel();
        }
    }
}
