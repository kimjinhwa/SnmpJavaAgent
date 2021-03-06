/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - TDomainAddressFactoryImpl.java  
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

package org.snmp4j.agent.mo.snmp;

import org.snmp4j.log.LogAdapter;
import org.snmp4j.log.LogFactory;
import org.snmp4j.smi.*;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

/**
 * The TDomainAddressFactoryImpl provides a standard implementation for the transport addresses of the
 * TRANSPORT-ADDRESS-MIB
 */
public class TDomainAddressFactoryImpl implements TDomainAddressFactory {

    private static final LogAdapter logger =
            LogFactory.getLogger(TDomainAddressFactoryImpl.class);

    public TDomainAddressFactoryImpl() {
    }

    public Address createAddress(OID transportDomain, OctetString address) {
        boolean isTCP = false;
        boolean isUDP = false;
        boolean isDNS = false;
        if (TransportDomains.snmpUDPDomain.equals(transportDomain) ||
                TransportDomains.transportDomainUdpIpv4.equals(transportDomain) ||
                TransportDomains.transportDomainUdpIpv6.equals(transportDomain)) {
            isUDP = true;
        } else if (TransportDomains.transportDomainUdpDns.equals(transportDomain)) {
            isUDP = true;
            isDNS = true;
        } else if (TransportDomains.transportDomainTcpIpv4.equals(transportDomain) ||
                TransportDomains.transportDomainTcpIpv6.equals(transportDomain)) {
            isTCP = true;
        } else if (TransportDomains.transportDomainTcpDns.equals(transportDomain)) {
            isDNS = true;
            isTCP = true;
        }
        TransportIpAddress transportIpAddress = null;
        if (isTCP) {
            transportIpAddress = new TcpAddress();
        } else if (isUDP) {
            transportIpAddress = new UdpAddress();
        }
        if (transportIpAddress != null) {
            try {
                if (isDNS) {
                    // By  RFC 3419 (TRANSPORT-ADDRESS-MIB) the address string should be ASCII, thus a conversion with toString()
                    // is OK. We could use toASCII(..) instead, but that will cause issues with UTF-8 domains.
                    String addressString = address.toString();
                    int colonIndex = addressString.lastIndexOf(':');
                    if (colonIndex <= 0) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Invalid TransportAddress format '" + address +
                                    "' for domain " + transportDomain + ": missing colon or empty DNS name");
                        }
                        return null;
                    }
                    int port = Integer.parseInt(addressString.substring(colonIndex + 1));
                    transportIpAddress.setInetAddress(InetAddress.getByName(addressString.substring(0, colonIndex)));
                    transportIpAddress.setPort(port);
                } else {
                    transportIpAddress.setTransportAddress(address);
                }
            } catch (Exception ex) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Invalid TransportAddress format '" + address + "' for domain " + transportDomain);
                }
                return null;
            }
            return transportIpAddress;
        }
        return null;
    }

    public boolean isValidAddress(OID transportDomain, OctetString address) {
        try {
            Address addr = createAddress(transportDomain, address);
            if (addr != null) {
                return true;
            }
        } catch (Exception ex) {
            logger.debug("Address is not valid TDomain address: " + address +
                    "; details: " + ex.getMessage());
        }
        return false;
    }

    public OID[] getTransportDomain(Address address) {
        if (address instanceof TransportIpAddress) {
            TransportIpAddress tipaddr = (TransportIpAddress) address;
            if (tipaddr.getInetAddress() instanceof Inet4Address) {
                if (address instanceof UdpAddress) {
                    return new OID[]{
                            TransportDomains.transportDomainUdpIpv4, TransportDomains.transportDomainUdpDns,
                            TransportDomains.snmpUDPDomain};
                } else if (address instanceof TcpAddress) {
                    return new OID[]{TransportDomains.transportDomainTcpIpv4, TransportDomains.transportDomainTcpDns};
                } else if (address instanceof TlsAddress) {
                    return new OID[]{TransportDomains.snmpTLSTCPDomain};
                }
            } else if (tipaddr.getInetAddress() instanceof Inet6Address) {
                if (address instanceof UdpAddress) {
                    return new OID[]{
                            TransportDomains.transportDomainUdpIpv6, TransportDomains.transportDomainUdpDns,
                            TransportDomains.snmpUDPDomain};
                } else if (address instanceof TcpAddress) {
                    return new OID[]{TransportDomains.transportDomainTcpIpv6, TransportDomains.transportDomainTcpDns};
                }
            }
        }
        return null;
    }

    public OctetString getAddress(Address address) {
        if (address instanceof TransportIpAddress) {
            TransportIpAddress tipaddr = (TransportIpAddress) address;
            byte[] addrBytes = tipaddr.getInetAddress().getAddress();
            OctetString addr = new OctetString(addrBytes);
            addr.append((byte) (tipaddr.getPort() >> 8));
            addr.append((byte) (tipaddr.getPort() & 0xFF));
            return addr;
        }
        return null;
    }

}
