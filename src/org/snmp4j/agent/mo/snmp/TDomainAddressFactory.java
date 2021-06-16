/*_############################################################################
  _## 
  _##  SNMP4J-Agent 3 - TDomainAddressFactory.java  
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

import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Address;

/**
 * The {@code TDomainAddressFactory} defines the interface for address
 * factories that can create an address from a transport domain ID and a
 * TDomainAddress textual convention conforming {@code OctetString} value
 * and vice versa.
 *
 * @author Frank Fock
 * @version 1.0
 */
public interface TDomainAddressFactory {

  /**
   * Creates an {@code Address} from a transport domain ID and a
   * TDomainAddress textual convention conforming {@code OctetString}
   * value.
   * @param transportDomain
   *    a transport domain ID as defined by {@link TransportDomains}.
   * @param address
   *    a TDomainAddress TC conforming {@code OctetString}.
   * @return
   *    an {@code Address} if {@code address} could be mapped or
   *    {@code null} if not.
   */
  Address createAddress(OID transportDomain, OctetString address);

  /**
   * Checks whether a transport domain ID and a {@code OctetString} value
   * represent a valid and consistent address.
   * @param transportDomain
   *    a transport domain ID as defined by {@link TransportDomains}.
   * @param address
   *    an {@code OctetString}.
   * @return
   *    {@code true} if {@code transportDomain} and
   *    {@code address} are consitent and valid.
   */
  boolean isValidAddress(OID transportDomain, OctetString address);

  /**
   * Gets the transport domain(s) ID for the specified address.
   *
   * @param address
   *    an address.
   * @return
   *    the corresponding transport domain ID as defined by
   *    {@link TransportDomains} or {@code null} if the address cannot be
   *    mapped.
   */
  OID[] getTransportDomain(Address address);

  /**
   * Gets the TDomainAddress textual convention conforming
   * {@code OctetString} value for the specified address.
   * @param address
   *    an address.
   * @return
   *    a TDomainAddress {@code OctetString} value or {@code null}
   *    if the address cannot be mapped.
   */
  OctetString getAddress(Address address);

}
