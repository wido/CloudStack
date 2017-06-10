/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.cloud.hypervisor.kvm.resource;

import junit.framework.TestCase;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Chain;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.FilterRef;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.FilterRef.Parameter;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Rule;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Rule.Action;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Rule.Direction;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Rule.Property;
import com.cloud.hypervisor.kvm.resource.LibvirtNWFilterDef.Rule.Property.Protocol;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class LibvirtNWFilterDefTest extends TestCase {

    public void testConstruct() {
        String uuid = "a605f65e-aa7b-4150-a790-f2b70acea205";
        String name = "mynetworkfilter";

        LibvirtNWFilterDef def = new LibvirtNWFilterDef(name, uuid);

        assertEquals(def.getName(), name);
        assertEquals(def.getUuid(), uuid);
        assertEquals(def.toString(), "<filter name='" + name + "'>\n<uuid>" + uuid + "</uuid>\n</filter>\n");
    }

    public void testConstructWithChain() {
        String uuid = "bbec2924-f327-40c4-abc3-fa07ca528695";
        String name = "mynetworkfilter";
        Chain chain = Chain.ROOT;

        LibvirtNWFilterDef def = new LibvirtNWFilterDef(name, uuid, chain);

        assertEquals(def.getName(), name);
        assertEquals(def.getUuid(), uuid);
        assertEquals(def.toString(),
                        "<filter name='" + name + "' chain='" + chain.toString() + "'>\n" +
                        "<uuid>" + uuid + "</uuid>\n</filter>\n");
    }

    public void testEmptyRule() {
        String uuid = "91158295-6b01-4946-86f2-748034de55b5";
        String name = "mynetworkfilter";
        Chain chain = Chain.ROOT;
        Action action = Action.ACCEPT;
        Direction direction = Direction.IN;

        LibvirtNWFilterDef filter = new LibvirtNWFilterDef(name, uuid, chain);
        Rule rule = new Rule(Action.ACCEPT, Direction.IN);
        filter.addRule(rule);
        assertEquals(filter.toString(),
                        "<filter name='" + name + "' chain='" + chain.toString() + "'>\n<uuid>" + uuid + "</uuid>\n" +
                        "<rule action='" + action.toString() + "' direction='" + direction.toString() + "'>\n" +
                        "</rule>\n</filter>\n");
    }

    public void testEmptyRuleWithPriority() {
        String uuid = "6530e1de-bf73-4cb3-812c-778da0c05113";
        String name = "mynetworkfilter";
        int priority = 100;
        Chain chain = Chain.ROOT;
        Action action = Action.ACCEPT;
        Direction direction = Direction.IN;

        LibvirtNWFilterDef filter = new LibvirtNWFilterDef(name, uuid, chain);
        Rule rule = new Rule(Action.ACCEPT, Direction.IN, priority);
        filter.addRule(rule);
        assertEquals(filter.toString(),
                        "<filter name='" + name + "' chain='" + chain.toString() + "'>\n<uuid>" + uuid + "</uuid>\n" +
                        "<rule action='" + action.toString() + "' direction='" + direction.toString() +
                        "' priority='" + priority + "'>\n</rule>\n</filter>\n");
    }

    public void testRulesWithProperties() {
        String uuid = "6530e1de-bf73-4cb3-812c-778da0c05113";
        String name = "mynetworkfilter";
        int priority = 100;
        Chain chain = Chain.ROOT;
        Action action = Action.ACCEPT;
        Direction direction = Direction.IN;
        Protocol protocol = Protocol.IP;
        int port = 22;

        LibvirtNWFilterDef filter = new LibvirtNWFilterDef(name, uuid, chain);
        Rule rule = new Rule(Action.ACCEPT, Direction.IN, priority);

        Property property = new Property(protocol);
        property.setDstportstart(port);

        rule.addProperty(property);

        filter.addRule(rule);

        assertEquals(filter.toString(),
                "<filter name='" + name + "' chain='" + chain.toString() + "'>\n<uuid>" + uuid + "</uuid>\n" +
                        "<rule action='" + action.toString() + "' direction='" + direction.toString() +
                        "' priority='" + priority + "'>\n<" + protocol.toString() + " dstportstart='" + port + "' />\n</rule>\n</filter>\n");
    }

    public void testManyRules() {
        String uuid = "8581ab95-7099-46da-9761-7500c7719a45";
        String name = "mynetworkfilter";
        Chain chain = Chain.IPV4;

        LibvirtNWFilterDef filter = new LibvirtNWFilterDef(name, uuid, chain);

        Rule rule1 = new Rule(Action.ACCEPT, Direction.IN, 100);
        Property property1 = new Property(Protocol.ICMP);
        rule1.addProperty(property1);

        Rule rule2 = new Rule(Action.ACCEPT, Direction.IN, 110);
        Property property2 = new Property(Protocol.TCP);
        property2.setDstportstart(22);
        property2.addState(Property.State.NEW);
        property2.addState(Property.State.ESTABLISHED);
        rule2.addProperty(property2);

        Rule rule3 = new Rule(Action.ACCEPT, Direction.IN, 120);
        Property property3 = new Property(Protocol.TCP);
        property3.setDstportstart(80);
        rule3.addProperty(property3);

        Rule rule4 = new Rule(Action.ACCEPT, Direction.IN, 130);
        Property property4 = new Property(Protocol.TCP);
        property4.setDstportstart(20);
        property4.setDstportend(21);
        rule4.addProperty(property4);

        Rule rule5 = new Rule(Action.DROP, Direction.IN, 1000);
        Property property5 = new Property(Protocol.ALL);
        rule5.addProperty(property5);

        filter.addFilterRef(new FilterRef("allow-dhcp"));
        filter.addRule(rule1);
        filter.addRule(rule2);
        filter.addRule(rule3);
        filter.addRule(rule4);
        filter.addRule(rule5);

        assertEquals(filter.toString(), "<filter name='mynetworkfilter' chain='ipv4'>\n" +
                "<uuid>8581ab95-7099-46da-9761-7500c7719a45</uuid>\n" +
                "<filterref filter='allow-dhcp'>\n" +
                "</filterref>\n" +
                "<rule action='accept' direction='in' priority='100'>\n" +
                "<icmp />\n" +
                "</rule>\n" +
                "<rule action='accept' direction='in' priority='110'>\n" +
                "<tcp dstportstart='22' state='NEW,ESTABLISHED' />\n" +
                "</rule>\n" +
                "<rule action='accept' direction='in' priority='120'>\n" +
                "<tcp dstportstart='80' />\n" +
                "</rule>\n" +
                "<rule action='accept' direction='in' priority='130'>\n" +
                "<tcp dstportstart='20' dstportend='21' />\n" +
                "</rule>\n" +
                "<rule action='drop' direction='in' priority='1000'>\n" +
                "<all />\n" +
                "</rule>\n" +
                "</filter>\n");
    }

    public void testICMPRules() {
        Rule rule;
        Property property;

        rule = new Rule(Action.ACCEPT, Direction.IN, 100);
        property = new Property(Protocol.ICMP);
        rule.addProperty(property);
        assertEquals(rule.toString(), "<rule action='accept' direction='in' priority='100'>\n" +
                "<icmp />\n</rule>\n");

        rule = new Rule(Action.ACCEPT, Direction.IN, 100);
        property = new Property(Protocol.ICMP);
        property.setCode(0);
        property.setType(8);
        rule.addProperty(property);
        assertEquals(rule.toString(), "<rule action='accept' direction='in' priority='100'>\n" +
                "<icmp type='8' code='0' />\n</rule>\n");
    }

    public void testTCPRules() {
        Rule rule;
        Property property;

        rule = new Rule(Action.ACCEPT, Direction.IN, 500);
        property = new Property(Protocol.TCP);
        property.setDstportstart(22);
        rule.addProperty(property);
        assertEquals(rule.toString(), "<rule action='accept' direction='in' priority='500'>\n" +
                "<tcp dstportstart='22' />\n</rule>\n");
    }

    public void testUDPRules() throws UnknownHostException {
        Rule rule;
        Property property;

        rule = new Rule(Action.ACCEPT, Direction.IN, 250);
        property = new Property(Protocol.UDP);
        property.setSrcipaddr(InetAddress.getByName("8.8.8.8"));
        property.setDstportstart(53);
        rule.addProperty(property);
        assertEquals(rule.toString(), "<rule action='accept' direction='in' priority='250'>\n" +
                "<udp srcipaddr='8.8.8.8' dstportstart='53' />\n</rule>\n");
    }

    public void testFilterRef() {
        FilterRef ref;
        ref = new FilterRef("no-arp");
        assertEquals(ref.toString(), "<filterref filter='no-arp'>\n</filterref>\n");

        ref = new FilterRef("no-ip-spoofing");
        ref.addParameter(new Parameter("IP", "192.168.1.100"));
        assertEquals(ref.toString(), "<filterref filter='no-ip-spoofing'>\n<parameter name='IP' value='192.168.1.100'/>\n</filterref>\n");
    }
}
