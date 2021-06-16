/*_############################################################################
  _## 
  _##  SNMP4J - AbstractTransportMapping.java  
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

import org.snmp4j.TransportMapping;
import org.snmp4j.MessageDispatcher;

import java.io.IOException;

import org.snmp4j.TransportStateReference;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;

import java.util.*;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The {@code AbstractTransportMapping} provides an abstract
 * implementation for the message dispatcher list and the maximum inbound
 * message size.
 *
 * @author Frank Fock
 * @version 3.0
 */
public abstract class AbstractTransportMapping<A extends Address> implements TransportMapping<A> {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractTransportMapping.class);

    protected List<TransportListener> transportListener = new ArrayList<TransportListener>(1);
    protected int maxInboundMessageSize = (1 << 16) - 1;
    protected boolean asyncMsgProcessingSupported = true;
    protected Set<A> suspendedAddresses = ConcurrentHashMap.newKeySet(5);

    public abstract Class<? extends Address> getSupportedAddressClass();

    /**
     * Sends a message to the supplied address using this transport. If the target address has been suspended,
     * then instead actually sending the message on the wire, the method
     * {@link #handleDroppedMessageToSend(Address, byte[], TransportStateReference, long, int)} will be called.
     * To stop suspending of a target address, call {@link #resumeAddress(Address)} for that address.
     *
     * @param address
     *         an {@code Address} instance denoting the target address.
     * @param message
     *         the whole message as an array of bytes.
     * @param tmStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     *
     * @throws IOException
     *         if any underlying IO operation fails.
     */
    public abstract void sendMessage(A address, byte[] message,
                                     TransportStateReference tmStateReference, long timeoutMillis, int maxRetries)
            throws IOException;

    public synchronized void addTransportListener(TransportListener l) {
        if (!transportListener.contains(l)) {
            List<TransportListener> tlCopy =
                    new ArrayList<TransportListener>(transportListener);
            tlCopy.add(l);
            transportListener = tlCopy;
        }
    }

    public synchronized void removeTransportListener(TransportListener l) {
        if (transportListener != null && transportListener.contains(l)) {
            List<TransportListener> tlCopy =
                    new ArrayList<TransportListener>(transportListener);
            tlCopy.remove(l);
            transportListener = tlCopy;
        }
    }

    protected void fireProcessMessage(A address, ByteBuffer buf,
                                      TransportStateReference tmStateReference) {
        if (transportListener != null) {
            for (TransportListener aTransportListener : transportListener) {
                aTransportListener.processMessage(this, address, buf, tmStateReference);
            }
        }
    }


    public abstract void close() throws IOException;

    /**
     * Suspend sending of messages to the specified address, regardless if a connection is already established or
     * not. To be able to send messages again to the specified address using
     * {@link #sendMessage(Address, byte[], TransportStateReference, long, int)}, call
     * {@link #resumeAddress(Address)}.
     * @param addressToSuspendSending
     *    an arbitrary remote address for which any messages send by
     *    {@link #sendMessage(Address, byte[], TransportStateReference, long, int)} should be dropped before sending
     *    and reopening a connection to that address.
     * @since 3.4.4
     */
    public void suspendAddress(A addressToSuspendSending) {
        if (suspendedAddresses.add(addressToSuspendSending)) {
            logger.info("Messages sending to "+addressToSuspendSending+" suspended");
        }
    }

    /**
     * Resume sending of messages to the specified address.
     * @param addressToResumeSending
     *    an arbitrary remote address for which any messages send by
     *    {@link #sendMessage(Address, byte[], TransportStateReference, long, int)} should be dropped before sending
     *    and reopening a connection to that address.
     * @return
     *    {@code true} if the specified address was previously suspended and is now resumed to allow sending messages,
     *    {@code false} otherwise.
     * @since 3.4.4
     */
    public boolean resumeAddress(A addressToResumeSending) {
        boolean resumed = suspendedAddresses.remove(addressToResumeSending);
        if (resumed) {
            logger.info("Messages sending to "+addressToResumeSending+" resumed");
        }
        return resumed;
    }

    /**
     * Handle a message that could not be send to the specified address, because there is no server socket for
     * receiving responses.
     * @param address
     *         an {@code Address} instance denoting the target address.
     * @param message
     *         the whole message as an array of bytes.
     * @param transportStateReference
     *         the (optional) transport model state reference as defined by
     *         RFC 5590 section 6.1.
     * @param timeoutMillis
     *         maximum number of milli seconds the connection creation might take (if connection based).
     * @param maxRetries
     *         maximum retries during connection creation.
     * @since 3.4.4
     */
    protected void handleDroppedMessageToSend(A address, byte[] message,
                                              TransportStateReference transportStateReference,
                                              long timeoutMillis, int maxRetries) {
        logger.warn("Dropped message, because this transport mapping is suspended: address="+
                address+", message="+ OctetString.fromByteArray(message).toHexString());
    }

    public abstract void listen() throws IOException;

    public int getMaxInboundMessageSize() {
        return maxInboundMessageSize;
    }

    /**
     * Returns {@code true} if asynchronous (multi-threaded) message
     * processing may be implemented. The default is {@code true}.
     *
     * @return if {@code false} is returned the
     * {@link MessageDispatcher#processMessage(org.snmp4j.TransportMapping, org.snmp4j.smi.Address, java.nio.ByteBuffer, org.snmp4j.TransportStateReference)}
     * method must not return before the message has been entirely processed.
     */
    public boolean isAsyncMsgProcessingSupported() {
        return asyncMsgProcessingSupported;
    }

    /**
     * Specifies whether this transport mapping has to support asynchronous
     * messages processing or not.
     *
     * @param asyncMsgProcessingSupported
     *         if {@code false} the {@link MessageDispatcher#processMessage(org.snmp4j.TransportMapping, org.snmp4j.smi.Address, java.nio.ByteBuffer, org.snmp4j.TransportStateReference)}
     *         method must not return before the message has been entirely processed,
     *         because the incoming message buffer is not copied before the message
     *         is being processed. If {@code true} the message buffer is copied
     *         for each call, so that the message processing can be implemented
     *         asynchronously.
     */
    public void setAsyncMsgProcessingSupported(
            boolean asyncMsgProcessingSupported) {
        this.asyncMsgProcessingSupported = asyncMsgProcessingSupported;
    }

}
