/*_############################################################################
  _## 
  _##  SNMP4J - AbstractTcpServerThread.java  
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

import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.util.WorkerTask;

import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.Map;

public abstract class AbstractTcpServerThread<S extends AbstractSocketEntry> implements WorkerTask {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractTcpServerThread.class);

    protected TcpTransportMapping<?> tcpTransportMapping;
    protected volatile boolean stop = false;
    protected Selector selector;
    protected final LinkedList<S> pending = new LinkedList<>();

    public AbstractTcpServerThread(TcpTransportMapping<?> tcpTransportMapping) throws IOException {
        this.tcpTransportMapping = tcpTransportMapping;
        selector = Selector.open();
    }

    protected void connectSocketToSendMessage(Address address, byte[] message,
                                              Socket s, S entry, Map<Address, S> sockets) {
        S currentSocketEntry = sockets.putIfAbsent(address, entry);
        if (currentSocketEntry != null && currentSocketEntry.getSocket().isConnected()) {
            entry = currentSocketEntry;
            if (logger.isDebugEnabled()) {
                logger.debug("Concurrent connection attempt detected, canceling this one to " + address);
            }
            entry.addMessage(message);
            try {
                s.close();
            }
            catch (IOException iox) {
                logger.error("Failed to close recently opened socket for '"+ address +"', with "+
                        iox.getMessage(), iox);
            }
            if (currentSocketEntry.getSocket().isConnected()) {
                queueNewMessage(entry);
                return;
            }
        }
        else if (currentSocketEntry != null && !currentSocketEntry.getSocket().isConnected()) {
            entry.insertMessages(currentSocketEntry.getMessages());
            sockets.put(address, entry);
            try {
                currentSocketEntry.getSocket().close();
            } catch (IOException iox) {
                logger.error("Failed to close socket for '"+ address +"', with "+
                        iox.getMessage(), iox);
            }
        }
        queueNewMessage(entry);
        logger.debug("Trying to connect to " + address);
    }

    private void queueNewMessage(S entry) {
        synchronized (pending) {
            pending.add(entry);
        }
        selector.wakeup();
    }

    public abstract void run();

    public abstract S removeSocketEntry(TcpAddress incomingAddress);

    @SuppressWarnings("unchecked")
    protected void connectChannel(SelectionKey sk, TcpAddress incomingAddress) {
        S entry = (S) sk.attachment();
        try {
            SocketChannel sc = (SocketChannel) sk.channel();
            if (!sc.isConnected()) {
                if (sc.finishConnect()) {
                    sc.configureBlocking(false);
                    logger.debug("Connected to " + entry.getPeerAddress());
                    // make sure connection is closed if not used for timeout
                    // micro seconds
                    tcpTransportMapping.timeoutSocket(entry);
                    entry.removeRegistration(selector, SelectionKey.OP_CONNECT);
                    entry.addRegistration(selector, SelectionKey.OP_WRITE);
                } else {
                    entry = null;
                }
            }
            if (entry != null) {
                Address addr = (incomingAddress == null) ?
                        entry.getPeerAddress() : incomingAddress;
                logger.debug("Fire connected event for " + addr);
                TransportStateEvent e =
                        new TransportStateEvent(tcpTransportMapping, addr, TransportStateEvent.STATE_CONNECTED,
                                null);
                tcpTransportMapping.fireConnectionStateChanged(e);
            }
        } catch (IOException iox) {
            logger.warn(iox);
            sk.cancel();
            closeChannel(sk.channel());
            if (entry != null) {
                pending.remove(entry);
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected TcpAddress writeData(SelectionKey sk, TcpAddress incomingAddress) {
        S entry = (S) sk.attachment();
        try {
            SocketChannel sc = (SocketChannel) sk.channel();
            incomingAddress =
                    new TcpAddress(sc.socket().getInetAddress(),
                            sc.socket().getPort());
            if ((entry != null) && (!entry.hasMessage())) {
                synchronized (pending) {
                    pending.remove(entry);
                    entry.removeRegistration(selector, SelectionKey.OP_WRITE);
                }
            }
            if (entry != null) {
                writeMessage(entry, sc);
            }
        } catch (IOException iox) {
            logger.warn(iox);
            // make sure channel is closed properly:
            closeChannel(sk.channel());
            removeSocketEntry(incomingAddress);
            TransportStateEvent e =
                    new TransportStateEvent(tcpTransportMapping, incomingAddress,
                            TransportStateEvent.STATE_DISCONNECTED_REMOTELY, iox);
            tcpTransportMapping.fireConnectionStateChanged(e);
        }
        return incomingAddress;
    }

    protected void closeChannel(SelectableChannel channel) {
        try {
            channel.close();
        } catch (IOException channelCloseException) {
            logger.warn(channelCloseException);
        }
    }

    private void writeMessage(S entry, SocketChannel sc) throws
            IOException {
        byte[] message = entry.nextMessage();
        if (message != null) {
            ByteBuffer buffer = ByteBuffer.wrap(message);
            sc.write(buffer);
            if (logger.isDebugEnabled()) {
                logger.debug("Sent message with length " +
                        message.length + " to " +
                        entry.getPeerAddress() + ": " +
                        new OctetString(message).toHexString());
            }
            entry.addRegistration(selector, SelectionKey.OP_READ);
        } else {
            entry.removeRegistration(selector, SelectionKey.OP_WRITE);
            // Make sure that we did not clear a selection key that was concurrently
            // added:
            if (entry.hasMessage() && !entry.isRegistered(SelectionKey.OP_WRITE)) {
                entry.addRegistration(selector, SelectionKey.OP_WRITE);
                logger.debug("Waking up selector");
                selector.wakeup();
            }
        }
    }

    public void close() {
        stop = true;
        WorkerTask st = tcpTransportMapping.getServer();
        if (st != null) {
            st.terminate();
        }
    }

    public void terminate() {
        stop = true;
        if (logger.isDebugEnabled()) {
            logger.debug("Terminated worker task: " + getClass().getName());
        }
    }

    public void join() {
        if (logger.isDebugEnabled()) {
            logger.debug("Joining worker task: " + getClass().getName());
        }
    }

    public void interrupt() {
        stop = true;
        if (logger.isDebugEnabled()) {
            logger.debug("Interrupting worker task: " + getClass().getName());
        }
        selector.wakeup();
    }
}
