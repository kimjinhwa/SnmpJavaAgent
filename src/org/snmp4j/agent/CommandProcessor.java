/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - CommandProcessor.java  
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

package org.snmp4j.agent;

import java.util.*;

import org.snmp4j.*;
import org.snmp4j.agent.mo.GenericManagedObject;
import org.snmp4j.agent.mo.lock.LockRequest;
import org.snmp4j.agent.request.*;
import org.snmp4j.agent.security.*;
import org.snmp4j.event.*;
import org.snmp4j.mp.*;
import org.snmp4j.smi.*;
import org.snmp4j.util.*;
import org.snmp4j.agent.util.TemporaryList;
import org.snmp4j.agent.mo.snmp.CoexistenceInfo;
import org.snmp4j.agent.mo.snmp.CoexistenceInfoProvider;
import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;

/**
 * The {@code CommandProcessor} is the central glue code that puts together
 * the various sub-systems of a SNMP agent.
 *
 * @author Frank Fock
 * @version 3.1
 */
public class CommandProcessor implements CommandResponder, NotificationOriginator {

    private static final LogAdapter logger =
            LogFactory.getLogger(CommandProcessor.class);

    /**
     * The maximum request timeout supported by this command processor
     * (by default 300.000 ms = 5 min).
     */
    private static final int MAX_INTERNAL_REQUEST_TIMEOUT = 300000;

    protected WorkerPool threadPool = null;
    protected VACM vacm = null;
    protected List<MOServer> moServers;
    protected List<OctetString> ownContextEngineIDs = new ArrayList<OctetString>(2);
    protected final List<RequestHandler<SnmpRequest>> pduHandler = new ArrayList<>();
    protected TemporaryList<SnmpRequest> requestList;
    protected RequestFactory<CommandResponderEvent<?>, PDU, SnmpRequest> requestFactory;
    protected NotificationOriginator notificationOriginator;
    protected ProxyMap proxyForwarder;
    protected CoexistenceInfoProvider coexistenceProvider;

    private transient List<CounterListener> counterListeners;

    /**
     * Creates a {@code CommandProcessor} and registers all PDU types
     * with the supplied contextEngineID as well as with
     * {@link MPv3#LOCAL_ENGINE_ID} as required by RFC 5343.
     *
     * @param contextEngineID
     *         the custom engine ID to use (should equal the engineID
     *         of the agent, i.e. USM).
     */
    public CommandProcessor(OctetString contextEngineID) {
        this.ownContextEngineIDs.add(contextEngineID);
        this.ownContextEngineIDs.add(MPv3.LOCAL_ENGINE_ID);
        moServers = new ArrayList<>();
        requestList = new TemporaryList<>(MAX_INTERNAL_REQUEST_TIMEOUT);
        pduHandler.add(new GetHandler());
        pduHandler.add(new GetNextHandler());
        pduHandler.add(new SetHandler());
        pduHandler.add(new GetBulkHandler());
        requestFactory = new DefaultRequestFactory();
    }

    /**
     * Sets the internal request timeout. Any request must return within this
     * amount of milli-seconds. Default is five minutes.
     *
     * @param timeoutMillis
     *         the maximum number of milli-seconds a request can be processed.
     *
     * @since 1.3
     */
    public void setInternalRequestTimeout(int timeoutMillis) {
        requestList.setTimeout(timeoutMillis);
    }

    /**
     * Gets the internal request timeout millis.
     *
     * @return the maximum number of milli-seconds a request can be processed.
     * @since 1.3
     */
    public int getInternalRequestTimeout() {
        return requestList.getTimeout();
    }

    @Override
    public <A extends Address> void processPdu(CommandResponderEvent<A> event) {
        if (event.getPDU() != null) {
            CoexistenceInfo cinfo = null;
            OctetString sname = new OctetString(event.getSecurityName());
            if (event.getPDU() instanceof ScopedPDU) {
                ScopedPDU spdu = (ScopedPDU) event.getPDU();
                cinfo = new CoexistenceInfo(sname, spdu.getContextEngineID(), spdu.getContextName());
            } else if (coexistenceProvider != null) {
                CoexistenceInfo[] cinfos = coexistenceProvider.getCoexistenceInfo(sname);
                if ((cinfos != null) && (cinfos.length > 0)) {
                    for (CoexistenceInfo cinfo1 : cinfos) {
                        if (coexistenceProvider.passesFilter(event.getPeerAddress(), cinfo1)) {
                            cinfo = cinfo1;
                            break;
                        }
                    }
                    if (cinfo == null) {
                        logger.warn("Access attempt from " + event.getPeerAddress() +
                                " denied because of source address filtering");

                        fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpInBadCommunityNames));
                        return;
                    }
                    event.setMaxSizeResponsePDU(cinfo.getMaxMessageSize());
                } else {
                    if (logger.isInfoEnabled()) {
                        logger.info("Community name '" + sname + "' not found in SNMP-COMMUNITY-MIB");
                    }
                    fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpInBadCommunityNames));
                    return;
                }
            }
            if ((cinfo == null) || (ownContextEngineIDs.contains(cinfo.getContextEngineID()))) {
                event.setProcessed(true);
                Command<A> command = new Command<>(event, cinfo);
                if (threadPool != null) {
                    threadPool.execute(command);
                } else {
                    command.run();
                }
            } else if (proxyForwarder != null) {
                ProxyForwardRequest<A> request = new ProxyForwardRequest<>(event, cinfo);
                ProxyForwarder proxy = proxyForwarder.get(cinfo.getContextEngineID(), request.getProxyType());
                ProxyCommand<A> command = new ProxyCommand<>(proxy, request);
                if (proxy != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Processsing proxy request with proxy forwarder " +
                                proxy);
                    }
                    if (threadPool != null) {
                        threadPool.execute(command);
                    } else {
                        command.run();
                    }
                } else {
                    fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpProxyDrops));
                }
            } else {
                fireIncrementCounter(new CounterEvent(this, SnmpConstants.snmpSilentDrops));
            }
        }
    }

    /**
     * Sets the internal thread pool for task execution.
     *
     * @param threadPool
     *         a pool of workers/threads which can execute tasks.
     *
     * @deprecated Use {@link #setWorkerPool} instead
     */
    @Deprecated
    public void setThreadPool(WorkerPool threadPool) {
        this.threadPool = threadPool;
    }

    /**
     * Sets the internal thread pool for task execution.
     *
     * @param threadPool
     *         a pool of workers/threads which can execute tasks.
     *
     * @since 1.9
     */
    public void setWorkerPool(WorkerPool threadPool) {
        this.threadPool = threadPool;
    }

    public VACM getVacm() {
        return vacm;
    }

    public void setVacm(VACM vacm) {
        this.vacm = vacm;
    }

    public OctetString getContextEngineID() {
        return ownContextEngineIDs.get(0);
    }

    public void setContextEngineID(OctetString contextEngineID) {
        this.ownContextEngineIDs.set(0, contextEngineID);
    }

    /**
     * Sends notification/inform messages to all registered targets. This method
     * uses the internal {@link ThreadPool} to send the message(s) via the
     * {@code NotificationOriginator}
     * (see {@link #getNotificationOriginator}) to the targets specified by the
     * SnmpTargetMIB and SnmpNotificationMIB instances supplied to the
     * notification originator.
     *
     * @param context
     *         the context name of the context on whose behalf this notification has
     *         been generated.
     * @param notificationID
     *         the object ID that uniquely identifies this notification. For SNMPv1
     *         traps, the notification ID has to be build using the rules provided
     *         by RFC 2576.
     * @param vbs
     *         an array of {@code VariableBinding} instances representing the
     *         payload of the notification.
     *
     * @return an array of ResponseEvent instances or NotificationTask instance if
     * the notification has been send asynchronously. Since the
     * {@code NotificationOriginator} determines on behalf of the
     * SNMP-NOTIFICATION-MIB contents whether a notification is sent as
     * trap/notification or as inform request, the returned array will contain
     * an element for each addressed target, but only a response PDU for
     * inform targets.
     *
     * {@code null} will be returned when sending the notification failed
     * because there is no {@link NotificationOriginator} set.
     * <p>
     * NOTE: If this command processor is using a ThreadPool then the returned
     * object will be {@link NotificationTask} instance. If all response have
     * been received {@link Object#notify()} will be called on the returned
     * {@code NotificationTask} object by the sending thread.
     */
    public Object notify(final OctetString context,
                         final OID notificationID,
                         final VariableBinding[] vbs) {
        return notify(context, notificationID, null, vbs);
    }

    public Object notify(OctetString context, OID notificationID,
                         TimeTicks sysUpTime, VariableBinding[] vbs) {
        if (notificationOriginator != null) {
            NotificationTask notifyTask =
                    new NotificationTask(notificationOriginator,
                            context, notificationID,
                            sysUpTime, vbs);
            if (threadPool != null) {
                threadPool.execute(notifyTask);
                return notifyTask;
            } else {
                notifyTask.run();
                return notifyTask.getResponses();
            }
        } else {
            logger.warn("Could not sent notification '" + notificationID + "'=" +
                    Arrays.asList(vbs) + " because NotificationOriginator not set");
        }
        return null;
    }


    public void setNotificationOriginator(NotificationOriginator
                                                  notificationOriginator) {
        this.notificationOriginator = notificationOriginator;
    }

    public void setCoexistenceProvider(CoexistenceInfoProvider
                                               coexistenceProvider) {
        this.coexistenceProvider = coexistenceProvider;
    }

    public ProxyForwarder addProxyForwarder(ProxyForwarder proxyForwarder,
                                            OctetString contextEngineID,
                                            int proxyType) {
        if (this.proxyForwarder == null) {
            this.proxyForwarder = new ProxyMap();
        }
        return this.proxyForwarder.add(proxyForwarder, contextEngineID, proxyType);
    }

    public ProxyForwarder removeProxyForwarder(OctetString contextEngineID,
                                               int proxyType) {
        if (proxyForwarder != null) {
            return proxyForwarder.remove(contextEngineID, proxyType);
        }
        return null;
    }

    protected RequestHandler<SnmpRequest> getHandler(int pduType) {
        synchronized (pduHandler) {
            for (RequestHandler<SnmpRequest> handler : pduHandler) {
                if (handler.isSupported(pduType)) {
                    return handler;
                }
            }
        }
        return null;
    }

    protected <A extends Address> void dispatchCommand(CommandResponderEvent<A> command, CoexistenceInfo cinfo) {
        try {
            RequestHandler<SnmpRequest> handler = getHandler(command.getPDU().getType());
            if (handler != null) {
                processRequest(command, cinfo, handler);
            } else {
                sendUnknownPDUHandlersReport(command);
            }
        } catch (Exception ex) {
            logger.error("Failed to dispatch command "+command+ " with "+cinfo+": "+ex.getMessage(), ex);
        }
    }

    private void sendUnknownPDUHandlersReport(CommandResponderEvent<?> command) {
        logger.info("No PDU handler found for request " + command);
        CounterEvent counter =
                new CounterEvent(this, SnmpConstants.snmpUnknownPDUHandlers);
        fireIncrementCounter(counter);
        if ((command.getMessageProcessingModel() == MessageProcessingModel.MPv3) &&
                (command.getPDU() instanceof ScopedPDU)) {
            ScopedPDU request = (ScopedPDU) command.getPDU();
            ScopedPDU report = new ScopedPDU();
            report.setContextEngineID(request.getContextEngineID());
            report.setContextName(request.getContextName());
            report.setType(PDU.REPORT);
            report.add(new VariableBinding(counter.getOid(), counter.getCurrentValue()));
            sendResponse(command, report);
        } else {
            PDU resp = (PDU) command.getPDU().clone();
            resp.setErrorStatus(PDU.genErr);
            sendResponse(command, resp);
        }
    }

    protected <A extends Address> void processRequest(CommandResponderEvent<A> command, CoexistenceInfo cinfo,
                                                      RequestHandler<SnmpRequest> handler) {
        SnmpRequest req = requestFactory.createRequest(command, cinfo);
        requestList.add(req);

        MOServer server = null;
        OctetString context = req.getContext();
        OctetString viewName = getViewName(command, cinfo, req.getViewType());
        if (viewName == null) {
            setAuthorizationError(req, VACM.VACM_NO_SUCH_VIEW);
        } else {
            req.setViewName(viewName);
            server = getServer(context);
            processRequest(server, handler, req);
        }
        finalizeRequest(command, req, server);
    }

    protected void reprocessRequest(MOServer server, SnmpRequest req) {
        RequestHandler<SnmpRequest> handler =
                getHandler(req.getSource().getPDU().getType());
        if (handler != null) {
            req.resetProcessedStatus();
            req.incReprocessCounter();
            processRequest(server, handler, req);
        } else {
            sendUnknownPDUHandlersReport(req.getSource());
        }
    }

    /**
     * Processes (or re-process) a request and try to complete the request (thus
     * to complete any incomplete subrequests).
     *
     * @param server
     *         the {@code MOServer} instance to use for accessing instrumentation.
     * @param handler
     *         the {@code RequestHandler} to use to process the request.
     * @param req
     *         the {@code Request}.
     * @param <R>
     *         the {@code Request} type to process.
     * @param <Source>
     *         the source object that created the request for processing.
     * @param <Response>
     *         the response PDU type created by the request processing.
     */
    protected <R extends Request<Source, Response, ? extends SubRequest<?>>, Source, Response>
    void processRequest(MOServer server, RequestHandler<R> handler, R req) {
        if (server == null) {
            logger.error("No server for " + req.getContext() +
                    " found -> request cannot be processed");
            req.setErrorStatus(SnmpConstants.SNMP_ERROR_GENERAL_ERROR);
        } else {
            handler.processPdu(req, server);
        }
    }

    protected <A extends Address> void finalizeRequest(CommandResponderEvent<A> command, SnmpRequest req,
                                                       MOServer server) {
        if (req.isComplete()) {
            requestList.remove(req);
            // send response
            sendResponse(command, req.getResponse());
            if (server != null) {
                release(server, req);
            }
        }
    }

    protected void release(MOServer server, SnmpRequest req) {
        for (Iterator<SnmpRequest.SnmpSubRequest> it = req.iterator(); it.hasNext(); ) {
            SnmpRequest.SnmpSubRequest sreq = it.next();
            if (sreq.getTargetMO() != null) {
                server.unlock(req, sreq.getTargetMO());
            }
        }
    }

    protected <A extends Address> void sendResponse(CommandResponderEvent<A> requestEvent, PDU response) {
        MessageDispatcher disp = requestEvent.getMessageDispatcher();
        try {
            if (response.getBERLength() > requestEvent.getMaxSizeResponsePDU()) {
                // response is tooBig
                if (response.getType() != PDU.REPORT) {
                    if (requestEvent.getPDU().getType() == PDU.GETBULK) {
                        while ((response.size() > 0) &&
                                (response.getBERLength() >
                                        requestEvent.getMaxSizeResponsePDU())) {
                            response.trim();
                        }
                    } else {
                        response.clear();
                        response.setRequestID(requestEvent.getPDU().getRequestID());
                        response.setErrorStatus(PDU.tooBig);
                    }
                }
                if (response.getBERLength() > requestEvent.getMaxSizeResponsePDU()) {
                    fireIncrementCounter(new CounterEvent(this,
                            SnmpConstants.snmpSilentDrops));
                    return;
                }
            }
            StatusInformation status = new StatusInformation();
            StateReference<A> stateRef = requestEvent.getStateReference();
            if (stateRef == null) {
                logger.warn("No state reference available for requestEvent=" +
                        requestEvent + ". Cannot return response=" + response);
            } else {
                stateRef.setTransportMapping(requestEvent.getTransportMapping());
                disp.returnResponsePdu(requestEvent.getMessageProcessingModel(),
                        requestEvent.getSecurityModel(),
                        requestEvent.getSecurityName(),
                        requestEvent.getSecurityLevel(),
                        response,
                        requestEvent.getMaxSizeResponsePDU(),
                        requestEvent.getStateReference(),
                        status);
            }
        } catch (MessageException ex) {
            logger.error("Failed to send response to request " + requestEvent, ex);
        }
    }

    protected void setAuthorizationError(Request<?,?,?> req, int vacmStatus) {
        if (logger.isInfoEnabled()) {
            logger.info("Request failed with VACM error "+vacmStatus+": "+req);
        }
        if (req.size() > 0) {
            SubRequest<?> sreq = req.iterator().next();
            sreq.getStatus().setErrorStatus(PDU.authorizationError);
        } else {
            req.setErrorStatus(PDU.authorizationError);
        }
    }

    public void addPduHandler(RequestHandler<SnmpRequest> handler) {
        pduHandler.add(handler);
    }

    public void removePduHandler(RequestHandler<SnmpRequest> handler) {
        pduHandler.remove(handler);
    }

    /**
     * Adds a {@link MOServer} to this command processor and returns {@code true} on success.
     * @param server
     *    the {@link MOServer} to add to this command processor with least priority.
     * @return
     *    {@code true} if the {@link MOServer} has been added, {@code false} if the {@link MOServer} is already
     *    present in this command processor.
     */
    public boolean addMOServer(MOServer server) {
        if (moServers.contains(server)) {
            if (logger.isWarnEnabled()) {
                logger.warn("Duplicate MOServer registration: "+server);
            }
            return false;
        }
        moServers.add(server);
        return true;
    }

    /**
     * Removes a {@link MOServer} from this command processor and returns {@code true} on success.
     * @param server
     *    the {@link MOServer} to remove from this command processor.
     * @return
     *    {@code true} if the server has been removed, {@code false} if the server was not subject to command
     *    processing.
     */
    public boolean removeMOServer(MOServer server) {
        return moServers.remove(server);
    }

    /**
     * Gets a {@link MOServer} responsible for the specified context.
     * @param context
     *    a SNMPv3 context or {@code null} for the default context.
     * @return
     *    a {@link MOServer} that returns {@code true} on {@link MOServer#isContextSupported(OctetString)} for the
     *    supplied SNMPv3 context or {@code null} if such a {@code MOServer} instance does not exists.
     */
    public MOServer getServer(OctetString context) {
        for (MOServer s : moServers) {
            if (s.isContextSupported(context)) {
                return s;
            }
        }
        return null;
    }

    public TemporaryList<SnmpRequest> getRequestList() {
        return requestList;
    }

    public NotificationOriginator getNotificationOriginator() {
        return notificationOriginator;
    }

    public ProxyMap getProxyForwarder() {
        return proxyForwarder;
    }

    public CoexistenceInfoProvider getCoexistenceProvider() {
        return coexistenceProvider;
    }


    class Command<A extends Address> implements WorkerTask {

        private CommandResponderEvent<A> request;
        private CoexistenceInfo cinfo;

        public Command(CommandResponderEvent<A> event, CoexistenceInfo cinfo) {
            this.request = event;
            this.cinfo = cinfo;
        }

        public void run() {
            dispatchCommand(request, cinfo);
        }

        public void terminate() {
        }

        public void join() throws InterruptedException {
        }

        public void interrupt() {
        }
    }

    class ProxyCommand<A extends Address> implements WorkerTask {

        private ProxyForwardRequest<A> request;
        private ProxyForwarder forwarder;

        public ProxyCommand(ProxyForwarder forwarder, ProxyForwardRequest<A> event) {
            this.forwarder = forwarder;
            this.request = event;
        }

        public void run() {
            if (forwarder.forward(request)) {
                PDU response = request.getResponsePDU();
                if (response != null) {
                    sendResponse(request.getCommandEvent(), response);
                }
            } else if (request.getProxyType() != ProxyForwarder.PROXY_TYPE_NOTIFY) {
                // proxy drop
                CounterEvent cevent = new CounterEvent(this, SnmpConstants.snmpProxyDrops);
                fireIncrementCounter(cevent);
                CommandResponderEvent<A> cre = request.getCommandEvent();
                if ((cre.getMessageProcessingModel() == MPv3.ID) &&
                        (cre.getStateReference() != null)) {
                    ScopedPDU reportPDU = new ScopedPDU();
                    reportPDU.setType(PDU.REPORT);
                    reportPDU.setContextEngineID(request.getContextEngineID());
                    reportPDU.setContextName(request.getContext());
                    reportPDU.add(new VariableBinding(SnmpConstants.snmpProxyDrops,
                            cevent.getCurrentValue()));
                    sendResponse(request.getCommandEvent(), reportPDU);
                }
            }
        }

        public void terminate() {
            // we cannot terminate (gracefully) this task while it is being executed
        }

        public void join() throws InterruptedException {
        }

        public void interrupt() {
        }
    }

    protected OctetString getViewName(CommandResponderEvent<?> req, CoexistenceInfo cinfo, int viewType) {
        return vacm.getViewName(cinfo.getContextName(),
                cinfo.getSecurityName(),
                req.getSecurityModel(),
                req.getSecurityLevel(),
                viewType);
    }

    protected void processNextSubRequest(SnmpRequest request, MOServer server, OctetString context, SubRequest<?> sreq)
            throws NoSuchElementException {
        // We can be sure to have a default context scope here because
        // the inner class SnmpSubRequest creates it!
        DefaultMOContextScope scope = (DefaultMOContextScope) sreq.getScope();
        MOQuery query = sreq.getQuery();
        if (query == null) {
            query = new VACMQuery(context,
                    scope.getLowerBound(),
                    scope.isLowerIncluded(),
                    scope.getUpperBound(),
                    scope.isUpperIncluded(),
                    request.getViewName(),
                    false,
                    request);
            sreq.setQuery(query);
        }
        ManagedObject<SubRequest<?>> mo;
        LockRequest lockRequest = new LockRequest(request, requestList.getTimeout());
        MOServerLookupEvent lookupEvent = new MOServerLookupEvent(this, null,
                query, MOServerLookupEvent.IntendedUse.getNext, true);
        while (!sreq.getStatus().isProcessed()) {
            mo = server.lookup(query, lockRequest, lookupEvent, GenericManagedObject.class);
            if (mo == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug("EndOfMibView at scope=" + scope + " and query " + query);
                }
                sreq.getVariableBinding().setVariable(Null.endOfMibView);
                sreq.getStatus().setPhaseComplete(true);
                continue;
            }
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Processing NEXT query " + query + " with " + mo +
                            " sub-request with index " + sreq.getIndex());
                }
                boolean counter64Skip = false;
                if ((!mo.next(sreq)) ||
                        (counter64Skip = ((request.getMessageProcessingModel() == MPv1.ID) &&
                                (sreq.getVariableBinding().getSyntax() ==
                                        SMIConstants.SYNTAX_COUNTER64)))) {
                    sreq.getVariableBinding().setVariable(Null.instance);
                    if (counter64Skip) {
                        scope.lowerBound = sreq.getVariableBinding().getOid();
                        scope.lowerIncluded = false;
                        sreq.getStatus().setProcessed(false);
                    } else {
                        scope.substractScope(mo.getScope());
                        // don't forget to update VACM query:
                        query.substractScope(mo.getScope());
                    }
                }
            } catch (Exception moex) {
                if (logger.isDebugEnabled()) {
                    moex.printStackTrace();
                }
                logger.error("Exception occurred while executing NEXT query: " +
                        moex.getMessage(), moex);
                if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                    sreq.getStatus().setErrorStatus(PDU.genErr);
                }
                if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                    throw new RuntimeException(moex);
                }
            } finally {
                unlockManagedObjectIfLockedByLookup(server, mo, lockRequest);
            }
        }
    }

    /**
     * Unlock the provided {@link ManagedObject} if the also provided {@link LockRequest} indicates
     * that the managed object was locked by a preceding {@link MOServer#lookup(MOQuery, LockRequest)} operation.
     *
     * @param server
     *         a MOServer that put the lock.
     * @param mo
     *         the possibly locked managed object.
     * @param lockRequest
     *         the lock request with the status of the (potentially acquired) lock.
     *
     * @since 2.4.0
     */
    protected void unlockManagedObjectIfLockedByLookup(MOServer server, ManagedObject<?> mo, LockRequest lockRequest) {
        switch (lockRequest.getLockRequestStatus()) {
            case locked:
            case lockedAfterTimeout:
                server.unlock(lockRequest.getLockOwner(), mo);
        }
    }

    public synchronized void addCounterListener(CounterListener l) {
        if (counterListeners == null) {
            counterListeners = new ArrayList<>(2);
        }
        counterListeners.add(l);
    }

    public synchronized void removeCounterListener(CounterListener l) {
        if (counterListeners != null) {
            counterListeners.remove(l);
        }
    }

    protected void fireIncrementCounter(CounterEvent event) {
        if (counterListeners != null) {
            List<CounterListener> listeners = counterListeners;
            for (CounterListener listener : listeners) {
                listener.incrementCounter(event);
            }
        }
    }

    private static void initRequestPhase(Request<?,?,?> request) {
        if (request.getPhase() == Request.PHASE_INIT) {
            request.nextPhase();
        }
    }

    class GetNextHandler implements RequestHandler<SnmpRequest> {

        public void processPdu(SnmpRequest request, MOServer server) {
            initRequestPhase(request);
            OctetString context = request.getContext();
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                while (it.hasNext()) {
                    SubRequest<?> sreq = it.next();
                    processNextSubRequest(request, server, context, sreq);
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
                logger.error("SubRequest not found");
                request.setErrorStatus(PDU.genErr);
            }
        }


        public boolean isSupported(int pduType) {
            return (pduType == PDU.GETNEXT);
        }

    }

    class SetHandler implements RequestHandler<SnmpRequest> {

        @SuppressWarnings("unchecked")
        public void prepare(OctetString context, SnmpRequest request, MOServer server) {
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                LockRequest lockRequest = new LockRequest(request, requestList.getTimeout());
                while ((!request.isPhaseComplete()) && (it.hasNext())) {
                    SnmpSubRequest<?> sreq = it.next();
                    if (sreq.isComplete()) {
                        continue;
                    }
                    MOScope scope = sreq.getScope();
                    MOQuery query = sreq.getQuery();
                    if (query == null) {
                        // create a query for write access
                        query = new VACMQuery(context,
                                scope.getLowerBound(),
                                scope.isLowerIncluded(),
                                scope.getUpperBound(),
                                scope.isUpperIncluded(),
                                request.getViewName(),
                                true, request);
                        sreq.setQuery(query);
                    }
                    if (!query.getScope().isCovered(
                            new DefaultMOContextScope(context, scope))) {
                        sreq.getStatus().setErrorStatus(PDU.noAccess);
                    } else {
                        MOServerLookupEvent lookupEvent = new MOServerLookupEvent(this, null,
                                query, MOServerLookupEvent.IntendedUse.prepare, true);
                        sreq.setLookupEvent(lookupEvent);
                        ManagedObject<? super SnmpSubRequest<?>> mo =
                                server.lookup(query, lockRequest, lookupEvent, GenericManagedObject.class);
                        if (mo == null) {
                            if ((query instanceof VACMQuery) &&
                                    (!((VACMQuery) query).isAccessAllowed(scope.getLowerBound()))) {
                                sreq.getStatus().setErrorStatus(PDU.noAccess);
                            } else {
                                sreq.getStatus().setErrorStatus(PDU.noCreation);
                            }
                            break;
                        }
                        sreq.setTargetMO(mo);
                        if (lockRequest.getLockRequestStatus() == LockRequest.LockStatus.lockTimedOut) {
                            logger.warn("Set request " + request +
                                    " failed because " + mo + " could not be locked");
                            if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                                sreq.getStatus().setErrorStatus(PDU.genErr);
                            }
                        } else {
                            try {
                                mo.prepare(sreq);
                                lookupEvent.completedUse(sreq);
                            } catch (Exception moex) {
                                logger.error("Set request " + request +
                                                " failed with exception",
                                        moex);
                                if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                                    sreq.getStatus().setErrorStatus(PDU.genErr);
                                }
                                if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                                    throw new RuntimeException(moex);
                                }
                            }
                        }
                    }
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
                logger.error("Cannot find sub-request: ", nsex);
                request.setErrorStatus(PDU.genErr);
            }
        }

        public void processPdu(SnmpRequest request, MOServer server) {
            OctetString context = request.getContext();
            try {
                while (request.getPhase() < Request.PHASE_2PC_CLEANUP) {
                    int phase = request.nextPhase();
                    switch (phase) {
                        case Request.PHASE_2PC_PREPARE: {
                            prepare(context, request, server);
                            break;
                        }
                        case Request.PHASE_2PC_COMMIT: {
                            commit(context, request, server);
                            break;
                        }
                        case Request.PHASE_2PC_UNDO: {
                            undo(context, request, server);
                            break;
                        }
                        case Request.PHASE_2PC_CLEANUP: {
                            cleanup(context, request, server);
                            return;
                        }
                    }
                    if (!request.isPhaseComplete()) {
                        // request needs to be reprocessed later!
                        return;
                    }
                }
            } catch (Exception ex) {
                if (logger.isDebugEnabled()) {
                    ex.printStackTrace();
                }
                logger.error("Failed to process SET request, trying to clean it up...",
                        ex);
                if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                    throw new RuntimeException(ex);
                }
            }
            cleanup(context, request, server);
        }

        @SuppressWarnings("unchecked")
        protected void undo(OctetString context, SnmpRequest request, MOServer server) {
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                while (it.hasNext()) {
                    SnmpRequest.SnmpSubRequest sreq = it.next();
                    if (sreq.isComplete()) {
                        continue;
                    }
                    OID oid = sreq.getVariableBinding().getOid();
                    ManagedObject<? super SnmpRequest.SnmpSubRequest>  mo = sreq.getTargetMO();
                    MOServerLookupEvent lookupEvent = null;
                    if (mo == null) {
                        DefaultMOContextScope scope =
                                new DefaultMOContextScope(context, oid, true, oid, true);
                        lookupEvent = new MOServerLookupEvent(this, null,
                                new MOQueryWithSource(scope, true, request),
                                MOServerLookupEvent.IntendedUse.undo, true);
                        sreq.setLookupEvent(lookupEvent);
                        mo = server.lookup(lookupEvent.getQuery(), null, lookupEvent, GenericManagedObject.class);
                    }
                    if (mo == null) {
                        sreq.getStatus().setErrorStatus(PDU.undoFailed);
                        continue;
                    }
                    try {
                        mo.undo(sreq);
                        if (lookupEvent != null) {
                            lookupEvent.completedUse(sreq);
                        }
                    } catch (Exception moex) {
                        if (logger.isDebugEnabled()) {
                            moex.printStackTrace();
                        }
                        logger.error(moex);
                        if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                            sreq.getStatus().setErrorStatus(PDU.undoFailed);
                        }
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(moex);
                        }
                    }
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
                logger.error("Cannot find sub-request: ", nsex);
                request.setErrorStatus(PDU.genErr);
            }
        }

        protected void commit(OctetString context, SnmpRequest request, MOServer server) {
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                while ((request.getErrorStatus() == PDU.noError) && (it.hasNext())) {
                    SnmpRequest.SnmpSubRequest sreq = it.next();
                    if (sreq.isComplete()) {
                        continue;
                    }
                    OID oid = sreq.getVariableBinding().getOid();
                    ManagedObject<? super SnmpRequest.SnmpSubRequest> mo = sreq.getTargetMO();
                    MOServerLookupEvent lookupEvent = null;
                    if (mo == null) {
                        DefaultMOContextScope scope =
                                new DefaultMOContextScope(context, oid, true, oid, true);
                        lookupEvent = new MOServerLookupEvent(this, null,
                                new MOQueryWithSource(scope, true, request),
                                MOServerLookupEvent.IntendedUse.commit, true);
                        mo = server.lookup(lookupEvent.getQuery(), null, lookupEvent, GenericManagedObject.class);
                    }
                    if (mo == null) {
                        sreq.getStatus().setErrorStatus(PDU.commitFailed);
                        continue;
                    }
                    try {
                        mo.commit(sreq);
                        if (lookupEvent != null) {
                            lookupEvent.completedUse(sreq);
                        }
                    } catch (Exception moex) {
                        if (logger.isDebugEnabled()) {
                            moex.printStackTrace();
                        }
                        logger.error(moex);
                        if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                            sreq.getStatus().setErrorStatus(PDU.commitFailed);
                        }
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(moex);
                        }
                    }
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
                logger.error("Cannot find sub-request: ", nsex);
                request.setErrorStatus(PDU.genErr);
            }
        }

        protected void cleanup(OctetString context,
                               SnmpRequest request,
                               MOServer server) {
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                while (it.hasNext()) {
                    SnmpRequest.SnmpSubRequest sreq = it.next();
                    if (sreq.isComplete()) {
                        continue;
                    }
                    OID oid = sreq.getVariableBinding().getOid();
                    ManagedObject<? super SnmpRequest.SnmpSubRequest> mo = sreq.getTargetMO();
                    MOServerLookupEvent lookupEvent = null;
                    if (mo == null) {
                        DefaultMOContextScope scope =
                                new DefaultMOContextScope(context, oid, true, oid, true);
                        lookupEvent = new MOServerLookupEvent(this, null,
                                new DefaultMOQuery(scope), MOServerLookupEvent.IntendedUse.cleanUp, true);
                        mo = server.lookup(lookupEvent.getQuery(), null, lookupEvent, GenericManagedObject.class);
                    }
                    if (mo == null) {
                        sreq.completed();
                        continue;
                    }
                    server.unlock(sreq.getRequest(), mo);
                    try {
                        mo.cleanup(sreq);
                        sreq.getStatus().setPhaseComplete(true);
                        if (lookupEvent != null) {
                            lookupEvent.completedUse(sreq);
                        }
                    } catch (Exception moex) {
                        if (logger.isDebugEnabled()) {
                            moex.printStackTrace();
                        }
                        logger.error(moex);
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(moex);
                        }
                    }
                }
            } catch (NoSuchElementException nsex) {
                logger.error("Cannot find sub-request: ", nsex);
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
            }
        }

        public boolean isSupported(int pduType) {
            return (pduType == PDU.SET);
        }

    }

    class GetHandler implements RequestHandler<SnmpRequest> {

        public boolean isSupported(int pduType) {
            return (pduType == PDU.GET);
        }

        public void processPdu(SnmpRequest request, MOServer server) {
            initRequestPhase(request);
            OctetString context = request.getContext();
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                LockRequest lockRequest = new LockRequest(request, requestList.getTimeout());
                while (it.hasNext()) {
                    SnmpRequest.SnmpSubRequest sreq = it.next();
                    MOScope scope = sreq.getScope();
                    MOQuery query = sreq.getQuery();
                    if (query == null) {
                        query = new VACMQuery(context,
                                scope.getLowerBound(),
                                scope.isLowerIncluded(),
                                scope.getUpperBound(),
                                scope.isUpperIncluded(),
                                request.getViewName(),
                                false, request);
                        sreq.setQuery(query);
                    }
                    MOServerLookupEvent lookupEvent = null;
                    lookupEvent = new MOServerLookupEvent(this, null,
                            query, MOServerLookupEvent.IntendedUse.get, true);
                    ManagedObject<? super SnmpRequest.SnmpSubRequest> mo =
                            server.lookup(query, lockRequest, lookupEvent, GenericManagedObject.class);
                    if (mo == null) {
                        sreq.getVariableBinding().setVariable(Null.noSuchObject);
                        sreq.getStatus().setPhaseComplete(true);
                        continue;
                    }
                    try {
                        mo.get(sreq);
                        if ((request.getMessageProcessingModel() == MPv1.ID) &&
                                (sreq.getVariableBinding().getSyntax() ==
                                        SMIConstants.SYNTAX_COUNTER64)) {
                            sreq.getVariableBinding().setVariable(Null.noSuchInstance);
                        }
                        lookupEvent.completedUse(sreq);
                    } catch (Exception moex) {
                        if (logger.isDebugEnabled()) {
                            moex.printStackTrace();
                        }
                        logger.warn(moex);
                        if (sreq.getStatus().getErrorStatus() == PDU.noError) {
                            sreq.getStatus().setErrorStatus(PDU.genErr);
                        }
                        if (SNMP4JSettings.isForwardRuntimeExceptions()) {
                            throw new RuntimeException(moex);
                        }
                    } finally {
                        unlockManagedObjectIfLockedByLookup(server, mo, lockRequest);
                    }
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    nsex.printStackTrace();
                }
                logger.error("SubRequest not found");
                request.setErrorStatus(PDU.genErr);
            }
        }

    }

    class GetBulkHandler implements RequestHandler<SnmpRequest> {

        public boolean isSupported(int pduType) {
            return (pduType == PDU.GETBULK);
        }

        public void processPdu(SnmpRequest request, MOServer server) {
            initRequestPhase(request);
            OctetString context = request.getContext();
            int nonRep = request.getNonRepeaters();
            try {
                Iterator<SnmpRequest.SnmpSubRequest> it = request.iterator();
                int i = 0;
                // non repeaters
                for (; ((i < nonRep) && it.hasNext()); i++) {
                    SnmpRequest.SnmpSubRequest sreq = it.next();
                    if (!sreq.isComplete()) {
                        processNextSubRequest(request, server, context, sreq);
                    }
                }
                // repetitions
                if (request.getMaxRepetitions() > 0) {
                    for (; it.hasNext(); i++) {
                        SnmpRequest.SnmpSubRequest sreq = it.next();
                        if (!sreq.isComplete()) {
                            processNextSubRequest(request, server, context, sreq);
                            sreq.updateNextRepetition();
                        }
                    }
                } else {
                    for (; it.hasNext(); i++) {
                        SnmpRequest.SnmpSubRequest sreq = it.next();
                        sreq.completed();
                    }
                }
            } catch (NoSuchElementException nsex) {
                if (logger.isDebugEnabled()) {
                    logger.debug("GETBULK request response PDU size limit reached");
                }
            }
        }
    }

    class VACMQuery extends MOQueryWithSource {

        private OctetString viewName;

        /**
         * Creates a VACMQuery for read-only access.
         *
         * @param context
         *         the context for the query, an empty OctetString denotes the default
         *         context.
         * @param lowerBound
         *         the lower bound OID.
         * @param isLowerIncluded
         *         indicates whether the lower bound should be included or not.
         * @param upperBound
         *         the upper bound OID or {@code null} if no upper bound is
         *         specified.
         * @param isUpperIncluded
         *         indicates whether the upper bound should be included or not.
         * @param viewName
         *         the view name to use for the query.
         * @param isWriteAccessIntended
         *         indicates if this query is issued on behalf of a SNMP SET request
         *         or not.
         * @param source
         *         the source ({@link Request}) object on whose behalf this query is
         *         executed.
         *
         * @since 1.1
         */
        public VACMQuery(OctetString context,
                         OID lowerBound, boolean isLowerIncluded,
                         OID upperBound, boolean isUpperIncluded,
                         OctetString viewName,
                         boolean isWriteAccessIntended,
                         SnmpRequest source) {
            super(new DefaultMOContextScope(context,
                            lowerBound, isLowerIncluded,
                            upperBound, isUpperIncluded),
                    isWriteAccessIntended, source);
            this.viewName = viewName;
        }

        public boolean isSearchQuery() {
            MOContextScope scope = getScope();
            return ((!scope.isLowerIncluded()) &&
                    ((scope.getUpperBound() == null) ||
                            (!scope.getUpperBound().equals(scope.getLowerBound()))));
        }

        public boolean matchesQuery(ManagedObject<?> managedObject) {
            OID oid;
            if (isSearchQuery()) {
                oid = managedObject.find(getScope());
                if (oid == null) {
                    return false;
                }
            } else {
                oid = getScope().getLowerBound();
            }
            return (vacm.isAccessAllowed(viewName, oid) == VACM.VACM_OK);
        }

        public boolean isAccessAllowed(OID oid) {
            return (vacm.isAccessAllowed(viewName, oid) == VACM.VACM_OK);
        }

        public String toString() {
            return super.toString() +
                    "[viewName=" + viewName + "]";
        }

    }

    static class DefaultRequestFactory implements RequestFactory<CommandResponderEvent<?>, PDU, SnmpRequest> {
        public SnmpRequest createRequest(CommandResponderEvent<?> initiatingEvent, CoexistenceInfo cinfo) {
            return new SnmpRequest(initiatingEvent, cinfo);
        }

    }

}
