/*_############################################################################
  _## 
  _##  SNMP4J - SnmpCompletableFuture.java  
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
package org.snmp4j.fluent;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.smi.Address;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;

public class SnmpCompletableFuture extends CompletableFuture<PDU> implements ResponseListener {

    public static final String ERR_TIMEOUT = "SNMP Request timed out";

    private ResponseEvent<?> responseEvent;
    private Object[] userObjects;

    protected String timeoutMessage = ERR_TIMEOUT;

    protected SnmpCompletableFuture() {
    }

    @Override
    public <A extends Address> void onResponse(ResponseEvent<A> event) {
        ((Session) event.getSource()).cancel(event.getRequest(), this);
        this.responseEvent = event;
        this.userObjects = (Object[])event.getUserObject();
        if (event.getError() != null) {
            completeExceptionally(event.getError());
        } else if (event.getResponse() == null) {
            completeExceptionally(new TimeoutException(timeoutMessage));
        } else if (event.getResponse().getType() == PDU.REPORT) {
            completeExceptionally(new ReportException((ScopedPDU) event.getResponse()));
        } else if (event.getResponse().getErrorStatus() != PDU.noError) {
            completeExceptionally(new SnmpErrorException(
                    event.getResponse().getErrorStatus(),
                    event.getResponse().getErrorIndex()));
        } else {
            complete(event.getResponse());
        }
    }

    public ResponseEvent<?> getResponseEvent() {
        return responseEvent;
    }

    public static <A extends Address> SnmpCompletableFuture send(Snmp snmp, Target<A> target, PDU pdu,
                                                                 Object... userObjects) {
        SnmpCompletableFuture future = new SnmpCompletableFuture();
        try {
            snmp.send(pdu, target, userObjects, future);
            if (!pdu.isConfirmedPdu()) {
                future.complete(null);
            }
        }
        catch (IOException iox) {
            future.completeExceptionally(iox);
        }
        return future;
    }

    public Object[] getUserObjects() {
        return userObjects;
    }

    public static class ReportException extends Exception {
        private static final long serialVersionUID = 1539501546791678999L;
        private final ScopedPDU report;

        public ReportException(ScopedPDU report) {
            super("SNMP REPORT error: "+report);
            this.report = report;
        }

        public ScopedPDU getReport() {
            return report;
        }
    }

    public static class SnmpErrorException extends Exception {
        private static final long serialVersionUID = -2338397456373295345L;
        private final int errorStatus;
        private final int errorIndex;

        public SnmpErrorException(int errorStatus, int errorIndex) {
            super("SNMP error "+PDU.toErrorStatusText(errorStatus)+ " on index "+errorIndex);
            this.errorStatus = errorStatus;
            this.errorIndex = errorIndex;
        }

        public int getErrorStatus() {
            return errorStatus;
        }

        public int getErrorIndex() {
            return errorIndex;
        }

        public String getErrorMessage() {
            return PDU.toErrorStatusText(errorStatus);
        }

    }

}
