/*_############################################################################
  _## 
  _##  SNMP4J - AbstractSocketEntry.java  
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
import org.snmp4j.smi.TcpAddress;

import java.net.Socket;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.Selector;
import java.util.LinkedList;
import java.util.List;

public abstract class AbstractSocketEntry extends AbstractServerSocket<TcpAddress> {

    private static final LogAdapter logger = LogFactory.getLogger(AbstractSocketEntry.class);

    protected Socket socket;
    private volatile int registrations = 0;
    private LinkedList<byte[]> messages = new LinkedList<byte[]>();
    private volatile int busyLoops = 0;

    public AbstractSocketEntry(TcpAddress address, Socket socket) {
        super(address);
        this.socket = socket;
    }

    public synchronized void addRegistration(Selector selector, int opKey)
            throws ClosedChannelException {
        if ((this.registrations & opKey) == 0) {
            this.registrations |= opKey;
            if (logger.isDebugEnabled()) {
                logger.debug("Adding operation " + opKey + " for: " + toString());
            }
            socket.getChannel().register(selector, registrations, this);
        } else if (!socket.getChannel().isRegistered()) {
            this.registrations = opKey;
            if (logger.isDebugEnabled()) {
                logger.debug("Registering new operation " + opKey + " for: " + toString());
            }
            socket.getChannel().register(selector, opKey, this);
        }
    }

    public synchronized void removeRegistration(Selector selector, int opKey)
            throws ClosedChannelException {
        if ((this.registrations & opKey) == opKey) {
            this.registrations &= ~opKey;
            socket.getChannel().register(selector, this.registrations, this);
        }
    }

    public synchronized boolean isRegistered(int opKey) {
        return (this.registrations & opKey) == opKey;
    }

    public Socket getSocket() {
        return socket;
    }

    public LinkedList<byte[]> getMessages() {
        return messages;
    }

    public synchronized void addMessage(byte[] message) {
        this.messages.add(message);
    }

    public synchronized void insertMessages(List<byte[]> messages) {
        this.messages.addAll(0, messages);
    }

    public synchronized byte[] nextMessage() {
        if (this.messages.size() > 0) {
            return this.messages.removeFirst();
        }
        return null;
    }

    public synchronized boolean hasMessage() {
        return !this.messages.isEmpty();
    }

    public int nextBusyLoop() {
        return ++busyLoops;
    }

    public void resetBusyLoops() {
        busyLoops = 0;
    }

    public abstract String toString();

}
