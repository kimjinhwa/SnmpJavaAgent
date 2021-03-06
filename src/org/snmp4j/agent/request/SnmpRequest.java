/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - SnmpRequest.java  
  _## 
  _##  Copyright (C) 2005-2021  Frank Fock (SNMP4J.org)
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

package org.snmp4j.agent.request;

import java.util.*;

import org.snmp4j.*;
import org.snmp4j.agent.*;
import org.snmp4j.agent.security.*;
import org.snmp4j.mp.*;
import org.snmp4j.smi.*;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.agent.mo.snmp.CoexistenceInfo;

/**
 * The <code>SnmpRequest</code> class implements requests from a SNMP source.
 *
 * @author Frank Fock
 * @version 1.2
 */
public class SnmpRequest extends AbstractRequest<SnmpRequest.SnmpSubRequest, CommandResponderEvent<?>, PDU> {

    private static final LogAdapter logger =
            LogFactory.getLogger(SnmpRequest.class);

    public static final OctetString DEFAULT_CONTEXT = new OctetString();

    private CoexistenceInfo coexistenceInfo;
    private OctetString viewName;

    private static int nextTransactionID = 0;

    protected Map<Object, Object> processingUserObjects;

    public SnmpRequest(CommandResponderEvent<?> request, CoexistenceInfo cinfo) {
        super(request);
        this.coexistenceInfo = cinfo;
        correctRequestValues();
        this.transactionID = nextTransactionID();
    }

    public static synchronized int nextTransactionID() {
        return nextTransactionID++;
    }

    protected synchronized void setupSubRequests() {
        PDU pdu = source.getPDU();
        int capacity = pdu.size();
        int totalRepetitions = (pdu instanceof PDUv1) ? 0 :
                repeaterRowSize * pdu.getMaxRepetitions();
        subrequests = new ArrayList<>(capacity + totalRepetitions);
        if (response == null) {
            response = createResponse();
        }
        int numSubReq = capacity;
        if (pdu.getType() == PDU.GETBULK && pdu.getMaxRepetitions() < 1) {
            numSubReq = Math.min(numSubReq, pdu.getNonRepeaters());
        }
        for (int i = 0; i < numSubReq; i++) {
            SnmpSubRequest subReq = new SnmpSubRequest(source.getPDU().get(i), i);
            addSubRequest(subReq);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("SnmpSubRequests initialized: " + subrequests);
        }
    }

    /**
     * Returns the number of repetitions that are complete.
     *
     * @return the minimum <code>r</code> for which all
     * <code>i&lt;r*(pduSize-nonRepeaters)</code> {@link SubRequest}s
     * returned by {@link #get(int i)} return true on
     * {@link SubRequest#isComplete()}.
     */
    public synchronized int getCompleteRepetitions() {
        int i = 0;
        int repeaterCount = getRepeaterCount();
        if (repeaterCount <= 0) {
            return 0;
        }
        for (Iterator<SnmpSubRequest> it = subrequests.iterator(); it.hasNext(); i++) {
            SnmpSubRequest sreq = it.next();
            if (!sreq.isComplete()) {
                return i / repeaterCount;
            }
        }
        return i / repeaterCount;
    }

    public int getMaxRepetitions() {
        return source.getPDU().getMaxRepetitions();
    }

    public int getNonRepeaters() {
        return source.getPDU().getNonRepeaters();
    }

    private void addSubRequest(SnmpSubRequest subReq) {
        subrequests.add(subReq);
        response.add(subReq.getVariableBinding());
    }

    protected int getMaxPhase() {
        return (is2PC()) ? PHASE_2PC_CLEANUP : PHASE_1PC;
    }

    public int size() {
        return source.getPDU().size();
    }

    public void setRequestEvent(CommandResponderEvent<?> source) {
        this.source = source;
    }

    protected void assignErrorStatus2Response() {
        int errStatus = getErrorStatus();
        if (source.getMessageProcessingModel() == MessageProcessingModel.MPv1) {
            switch (errStatus) {
                case SnmpConstants.SNMP_ERROR_NOT_WRITEABLE:
                case SnmpConstants.SNMP_ERROR_NO_ACCESS:
                case SnmpConstants.SNMP_ERROR_NO_CREATION:
                case SnmpConstants.SNMP_ERROR_INCONSISTENT_NAME: {
                    response.setErrorStatus(SnmpConstants.SNMP_ERROR_NO_SUCH_NAME);
                    break;
                }
                case SnmpConstants.SNMP_ERROR_AUTHORIZATION_ERROR:
                case SnmpConstants.SNMP_ERROR_RESOURCE_UNAVAILABLE:
                case SnmpConstants.SNMP_ERROR_COMMIT_FAILED:
                case SnmpConstants.SNMP_ERROR_UNDO_FAILED: {
                    response.setErrorStatus(SnmpConstants.SNMP_ERROR_GENERAL_ERROR);
                    break;
                }
                case SnmpConstants.SNMP_ERROR_WRONG_VALUE:
                case SnmpConstants.SNMP_ERROR_WRONG_LENGTH:
                case SnmpConstants.SNMP_ERROR_INCONSISTENT_VALUE:
                case SnmpConstants.SNMP_ERROR_WRONG_TYPE: {
                    response.setErrorStatus(SnmpConstants.SNMP_ERROR_BAD_VALUE);
                    break;
                }
                default: {
                    response.setErrorStatus(errStatus);
                }
            }
            for (int i = 0; i < response.size(); i++) {
                VariableBinding vb = response.get(i);
                if (vb.isException()) {
                    response.setErrorStatus(PDU.noSuchName);
                    response.setErrorIndex(i + 1);
                    response.set(i, new VariableBinding(vb.getOid()));
                    return;
                }
            }
        } else {
            response.setErrorStatus(errStatus);
        }
        response.setErrorIndex(getErrorIndex());
    }

    private PDU createResponse() {
        PDU resp = (PDU) source.getPDU().clone();
        resp.clear();
        resp.setType(PDU.RESPONSE);
        resp.setRequestID(source.getPDU().getRequestID());
        resp.setErrorIndex(0);
        resp.setErrorStatus(PDU.noError);
        return resp;
    }

    private void correctRequestValues() {
        PDU request = source.getPDU();
        if (!(request instanceof PDUv1)) {
            if (request.getMaxRepetitions() < 0) {
                request.setMaxRepetitions(0);
            }
            if (request.getNonRepeaters() < 0) {
                request.setNonRepeaters(0);
            }
            if (request.getNonRepeaters() > request.size()) {
                request.setNonRepeaters(request.size());
            }
            repeaterStartIndex = request.getNonRepeaters();
            repeaterRowSize =
                    Math.max(request.size() - repeaterStartIndex, 0);
        } else {
            repeaterStartIndex = 0;
            repeaterRowSize = request.size();
        }
    }

    /**
     * Return the response PDU.
     *
     * @return the PDU received as response.
     */
    public PDU getResponse() {
        if (response == null) {
            response = createResponse();
        }
        assignErrorStatus2Response();
        return response;
    }

    /**
     * iterator
     *
     * @return Iterator
     */
    public Iterator<SnmpRequest.SnmpSubRequest> iterator() {
        initSubRequests();
        return new SnmpSubRequestIterator();
    }

    protected boolean is2PC() {
        return (source.getPDU().getType() == PDU.SET);
    }

    public OctetString getContext() {
        if (coexistenceInfo != null) {
            return coexistenceInfo.getContextName();
        } else if (source.getPDU() instanceof ScopedPDU) {
            return ((ScopedPDU) source.getPDU()).getContextName();
        }
        return DEFAULT_CONTEXT;
    }

    public OctetString getViewName() {
        return viewName;
    }

    public void setViewName(OctetString viewName) {
        this.viewName = viewName;
    }

    public int getSecurityLevel() {
        return source.getSecurityLevel();
    }

    public int getSecurityModel() {
        return source.getSecurityModel();
    }

    public OctetString getSecurityName() {
        if (coexistenceInfo != null) {
            return coexistenceInfo.getSecurityName();
        }
        return new OctetString(source.getSecurityName());
    }

    public int getViewType() {
        return getViewType(source.getPDU().getType());
    }

    /**
     * Returns the VACM view type for the supplied PDU type.
     *
     * @param pduType
     *         a PDU type.
     *
     * @return the corresponding VACM view type.
     */
    public static int getViewType(int pduType) {
        switch (pduType) {
            case PDU.GETNEXT:
            case PDU.GET:
            case PDU.GETBULK: {
                return VACM.VIEW_READ;
            }
            case PDU.INFORM:
            case PDU.TRAP:
            case PDU.V1TRAP: {
                return VACM.VIEW_NOTIFY;
            }
            default: {
                return VACM.VIEW_WRITE;
            }
        }
    }

    protected synchronized void addRepeaterSubRequest() {
        int predecessorIndex = subrequests.size() - repeaterRowSize;
        SnmpSubRequest sreq = new SnmpSubRequest(subrequests.get(predecessorIndex), subrequests.size());
        addSubRequest(sreq);
        if (logger.isDebugEnabled()) {
            logger.debug("Added sub request '" + sreq + "' to response '" + response + "'");
        }
    }

    public int getErrorIndex() {
        if (errorStatus == SnmpConstants.SNMP_ERROR_SUCCESS) {
            return 0;
        }
        initSubRequests();
        int index = 1;
        for (Iterator<SnmpRequest.SnmpSubRequest> it = subrequests.iterator(); it.hasNext(); index++) {
            SnmpRequest.SnmpSubRequest sreq = it.next();
            if (sreq.getStatus().getErrorStatus() != SnmpConstants.SNMP_ERROR_SUCCESS) {
                return index;
            }
        }
        return 0;
    }


    public int getTransactionID() {
        return transactionID;
    }

    public CoexistenceInfo getCoexistenceInfo() {
        return coexistenceInfo;
    }

    /**
     * Returns the last repetition row that is complete (regarding the number
     * of elements in the row) before the given subrequest index.
     *
     * @param upperBoundIndex
     *         the maximum sub-request index within the row to return.
     *
     * @return a sub list of the sub-requests list that contains the row's elements.
     * If no such row exists <code>null</code> is returned.
     */
    private List<SnmpSubRequest> lastRow(int upperBoundIndex) {
        if ((repeaterRowSize == 0) || (upperBoundIndex <= repeaterStartIndex)) {
            return null;
        }
        int rows = (upperBoundIndex - repeaterStartIndex) / repeaterRowSize;
        int startIndex = repeaterStartIndex + (repeaterRowSize * (rows - 1));
        int endIndex = repeaterStartIndex + (repeaterRowSize * rows);
        if ((startIndex < repeaterStartIndex) || (endIndex > subrequests.size())) {
            return null;
        }
        return subrequests.subList(startIndex, endIndex);
    }

    public int getMessageProcessingModel() {
        return this.source.getMessageProcessingModel();
    }

    public int getRepeaterCount() {
        PDU reqPDU = source.getPDU();
        return Math.max(reqPDU.size() - reqPDU.getNonRepeaters(), 0);
    }

    public boolean isPhaseComplete() {
        if (errorStatus == SnmpConstants.SNMP_ERROR_SUCCESS) {
            initSubRequests();
            for (SnmpRequest.SnmpSubRequest subrequest : subrequests) {
                RequestStatus status = subrequest.getStatus();
                if (status.getErrorStatus() != SnmpConstants.SNMP_ERROR_SUCCESS) {
                    return true;
                } else if (!status.isPhaseComplete()) {
                    return false;
                }
            }
        }
        if (source.getPDU().getType() == PDU.GETBULK) {
            SnmpSubRequestIterator it =
                    new SnmpSubRequestIterator(subrequests.size(), 1);
            return !it.hasNext();
        }
        return true;
    }

    public boolean isBulkRequest() {
        return (source.getPDU().getType() == PDU.GETBULK);
    }

    public synchronized Object getProcessingUserObject(Object key) {
        if (processingUserObjects != null) {
            return processingUserObjects.get(key);
        }
        return null;
    }

    public synchronized Object setProcessingUserObject(Object key, Object value) {
        if (processingUserObjects == null) {
            processingUserObjects = new HashMap<>(5);
        }
        return processingUserObjects.put(key, value);
    }

    /**
     * The {@link SnmpSubRequestIterator} implements an iterator over the GETBULK repetitions of a subrequest.
     *
     * @author Frank Fock
     * @version 3.0.4
     */
    public class SnmpSubRequestIterator implements SubRequestIterator<SnmpRequest.SnmpSubRequest> {

        private int cursor = 0;
        private int increment = 1;
        private boolean noAppending;

        protected SnmpSubRequestIterator() {
            this.cursor = 0;
        }

        protected SnmpSubRequestIterator(int offset, int increment) {
            this.cursor = offset;
            this.increment = increment;
        }

        protected void setNoAppending(boolean noAppending) {
            this.noAppending = noAppending;
        }

        /**
         * hasNext
         *
         * @return boolean
         */
        public boolean hasNext() {
            synchronized (SnmpRequest.this) {
                PDU reqPDU = source.getPDU();
                if (reqPDU.getType() == PDU.GETBULK) {
                    if (noAppending && (cursor >= subrequests.size())) {
                        return false;
                    }
                    if (cursor < Math.min(reqPDU.size(), reqPDU.getNonRepeaters())) {
                        return true;
                    } else {
                        if (cursor < reqPDU.getNonRepeaters() +
                                reqPDU.getMaxRepetitions() * getRepeaterCount()) {
                            List<SnmpSubRequest> lastRow = lastRow(cursor);
                            if (lastRow != null) {
                                boolean allEndOfMibView = true;
                                SnmpSubRequest sreq = null;
                                for (SnmpSubRequest creq : lastRow) {
                                    sreq = creq;
                                    if (sreq.getVariableBinding().getSyntax() !=
                                            SMIConstants.EXCEPTION_END_OF_MIB_VIEW) {
                                        allEndOfMibView = false;
                                        break;
                                    }
                                }
                                if (allEndOfMibView) {
                                    // truncate request if already more elements are there
                                    if ((sreq != null) && (sreq.getIndex() < subrequests.size())) {
                                        int lastElementIndex = sreq.getIndex();
                                        List<?> tail = subrequests.subList(lastElementIndex + 1,
                                                subrequests.size());
                                        tail.clear();
                                        tail = response.getVariableBindings().
                                                subList(lastElementIndex + 1, response.size());
                                        tail.clear();
                                    }
                                    return false;
                                }
                            }
                            return (response.getBERLength() <
                                    source.getMaxSizeResponsePDU());
                        } else if ((reqPDU.getNonRepeaters() == 0) &&
                                (reqPDU.getMaxRepetitions() == 0)) {
                            SnmpRequest.this.subrequests.clear();
                            if (response != null) {
                                while (response.size() > 0) {
                                    response.remove(0);
                                }
                            }
                        }
                    }
                    return false;
                }
                return (cursor < reqPDU.size());
            }
        }

        public SnmpRequest.SnmpSubRequest next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            if ((source.getPDU().getType() == PDU.GETBULK) &&
                    (cursor >= subrequests.size()) && (source.getPDU().getMaxRepetitions() > 0)) {
                while (cursor >= subrequests.size()) {
                    addRepeaterSubRequest();
                }
            }
            SnmpRequest.SnmpSubRequest sreq = subrequests.get(cursor);
            cursor += increment;
            return sreq;
        }

        public void remove() {
            throw new UnsupportedOperationException("Remove is not supported " +
                    "on sub-requests");
        }

        public boolean equals(Object other) {
            return ((other instanceof Request) &&
                    ((Request) other).getTransactionID() == getTransactionID());
        }

        public int hashCode() {
            return getTransactionID();
        }
    }


    /**
     * The SnmpSubRequest represents a single variable binding request of a SNMP PDU.
     *
     * @author Frank Fock
     * @version 3.0
     */
    public class SnmpSubRequest implements org.snmp4j.agent.request.SnmpSubRequest<SnmpSubRequest>, RequestStatusListener {

        private RequestStatus status;
        private VariableBinding vb;
        private Object undoValue;
        private MOScope scope;
        private ManagedObject<? super SnmpSubRequest> targetMO;
        private MOServerLookupEvent lookupEvent;
        private MOQuery query;
        private int index;

        private volatile Object userObject;

        protected SnmpSubRequest(VariableBinding subrequest, int index) {
            this.vb = subrequest;
            this.index = index;
            switch (source.getPDU().getType()) {
                case PDU.GETBULK:
                case PDU.GETNEXT: {
                    this.scope = getNextScope(new OID(this.vb.getOid()));
                    break;
                }
                default: {
                    OID oid = this.vb.getOid();
                    this.scope = new DefaultMOContextScope(getContext(),
                            oid, true, oid, true);
                }
            }
            status = new RequestStatus();
            status.addRequestStatusListener(this);
            if (logger.isDebugEnabled()) {
                logger.debug("Created subrequest " + index + " with scope " + scope +
                        " from " + subrequest);
            }
        }

        protected MOScope getNextScope(OID previousOID) {
            return new DefaultMOContextScope(getContext(), previousOID, false,
                    null, false);
        }

        protected SnmpSubRequest(org.snmp4j.agent.request.SnmpSubRequest<?> predecessor, int index) {
            this(new VariableBinding(predecessor.getVariableBinding().getOid()), index);
//    Do not copy queries because they need to be updated externally only!
//    this.query = predecessor.getQuery();
        }

        @Override
        public SnmpRequest getRequest() {
            return SnmpRequest.this;
        }

        public RequestStatus getStatus() {
            return status;
        }

        public VariableBinding getVariableBinding() {
            return vb;
        }

        public void setStatus(RequestStatus status) {
            this.status = status;
        }

        public Object getUndoValue() {
            return undoValue;
        }

        public void setUndoValue(Object undoInformation) {
            this.undoValue = undoInformation;
        }

        public void requestStatusChanged(RequestStatusEvent event) {
            int newStatus = event.getStatus().getErrorStatus();
            setErrorStatus(newStatus);
            if (logger.isDebugEnabled() &&
                    (newStatus != SnmpConstants.SNMP_ERROR_SUCCESS)) {
                new Exception("Error '" +
                        PDU.toErrorStatusText(event.getStatus().getErrorStatus()) +
                        "' generated at: " + vb).printStackTrace();
            }
        }

        public MOScope getScope() {
            return scope;
        }

        public void completed() {
            status.setPhaseComplete(true);
        }

        public boolean hasError() {
            return getStatus().getErrorStatus() != SnmpConstants.SNMP_ERROR_SUCCESS;
        }

        public boolean isComplete() {
            return status.isPhaseComplete();
        }

        public void setTargetMO(ManagedObject<? super SnmpSubRequest> managedObject) {
            this.targetMO = managedObject;
        }

        public ManagedObject<? super SnmpSubRequest> getTargetMO() {
            return targetMO;
        }

        public MOServerLookupEvent getLookupEvent() {
            return lookupEvent;
        }

        public void setLookupEvent(MOServerLookupEvent lookupEvent) {
            this.lookupEvent = lookupEvent;
        }

        public SnmpRequest getSnmpRequest() {
            return SnmpRequest.this;
        }

        public void setErrorStatus(int errorStatus) {
            SnmpRequest.this.setErrorStatus(errorStatus);
        }

        public int getIndex() {
            return index;
        }

        public void setQuery(MOQuery query) {
            this.query = query;
        }

        public MOQuery getQuery() {
            return query;
        }

        public String toString() {
            return getClass().getName() + "[scope=" + scope +
                    ",vb=" + vb + ",status=" + status + ",query=" + query + ",index=" + index +
                    ",targetMO=" + targetMO + ",lookupEvent=" + lookupEvent + "]";
        }

        public SubRequestIterator<SnmpSubRequest> repetitions() {
            return repetitions(false);
        }

        private SubRequestIterator<SnmpRequest.SnmpSubRequest> repetitions(boolean noAppending) {
            initSubRequests();
            if (isBulkRequest()) {
                int nonRepeaters = source.getPDU().getNonRepeaters();
                int repeaters = source.getPDU().size() - nonRepeaters;
                if (repeaters > 0) {
                    SnmpSubRequestIterator it = new SnmpSubRequestIterator(Math.max(getIndex(), nonRepeaters), repeaters);
                    it.setNoAppending(noAppending);
                    return it;
                }
            }
            return new SubRequestIteratorSupport<>(Collections.<Object>emptyList().iterator());
        }

        public void updateNextRepetition() {
            if (!isBulkRequest()) {
                return;
            }
            this.query = null;
            SubRequestIterator<SnmpSubRequest> repetitions = repetitions(true);
            // skip this one if there is any
            if (repetitions.hasNext()) {
                repetitions.next();
            }
            while (repetitions.hasNext()) {
                SnmpSubRequest nsreq = repetitions.next();
                if ((getStatus().getErrorStatus() == PDU.noError) &&
                        (!this.vb.isException())) {
                    nsreq.query = null;
                    nsreq.scope = getNextScope(this.vb.getOid());
                    nsreq.getVariableBinding().setOid(this.vb.getOid());
                } else if (this.vb.isException()) {
                    nsreq.query = null;
                    nsreq.getVariableBinding().setOid(this.vb.getOid());
                    nsreq.getVariableBinding().setVariable(this.vb.getVariable());
                    nsreq.getStatus().setPhaseComplete(true);
                }
            }
        }

        public final int getErrorStatus() {
            return getStatus().getErrorStatus();
        }

        public Object getUserObject() {
            return userObject;
        }

        public void setUserObject(Object userObject) {
            this.userObject = userObject;
        }

    }

}

