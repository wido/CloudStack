// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package com.cloud.hypervisor.kvm.resource;

import com.cloud.utils.StringUtils;

import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;

public class LibvirtNWFilterDef {
    public enum Chain {
        ROOT("root"), MAC("mac"), VLAN("vlan"), STP("stp"), IPV4("ipv4"), IPV6("ipv6"), ARP("arp"), RARP("rarp");
        String _chain;

        Chain(String chain) {
            _chain = chain;
        }

        @Override
        public String toString() {
            return _chain;
        }
    }

    private String name;
    private String uuid;
    private Chain chain;
    private List<Rule> rules = new ArrayList<>();
    private List<FilterRef> filterrefs = new ArrayList<>();

    public LibvirtNWFilterDef(String name, String uuid) {
        this.name = name;
        this.uuid = uuid;
    }

    public LibvirtNWFilterDef(String name, String uuid, Chain chain) {
        this.name = name;
        this.uuid = uuid;
        this.chain = chain;
    }

    public String getName() {
        return name;
    }

    public String getUuid() {
        return uuid;
    }

    public Chain getChain() {
        return chain;
    }

    public void addRule(Rule rule) {
        rules.add(rule);
    }

    public void addFilterRef(FilterRef filterref) {
        filterrefs.add(filterref);
    }

    @Override
    public String toString() {
        StringBuilder xml = new StringBuilder();
        if (getChain() == null) {
            xml.append("<filter name='" + getName() + "'>\n");
        } else {
            xml.append("<filter name='" + getName() + "' chain='" +  getChain().toString() + "'>\n");
        }

        xml.append("<uuid>" + uuid + "</uuid>\n");

        for (FilterRef filterref: filterrefs) {
            xml.append(filterref.toString());
        }

        for (Rule rule: rules) {
            xml.append(rule.toString());
        }

        xml.append("</filter>\n");
        return xml.toString();
    }

    public static class Rule {
        public enum Action {
            ACCEPT("accept"), REJECT("reject"), DROP("drop"), RETURN("return");
            String _action;

            Action(String action) {
                _action = action;
            }

            @Override
            public String toString() {
                return _action;
            }
        }

        public enum Direction {
            IN("in"), OUT("out"), INOUT("inout");
            String _direction;

            Direction(String direction) {
                _direction = direction;
            }

            @Override
            public String toString() {
                return _direction;
            }
        }

        private Action action;
        private Direction direction;
        private int priority;
        private List<Property> properties = new ArrayList<>();

        public Rule(Action action, Direction direction) {
            this.action = action;
            this.direction = direction;
        }

        public Rule(Action action, Direction direction, int priority) {
            this.action = action;
            this.direction = direction;
            this.priority = priority;
        }

        public void addProperty(Property property) {
            properties.add(property);
        }

        @Override
        public String toString() {
            StringBuilder xml = new StringBuilder();
            if (priority == 0) {
                xml.append("<rule action='" + action.toString() + "' direction='" + direction.toString() + "'>\n");
            } else {
                xml.append("<rule action='" + action.toString() + "' direction='" + direction.toString() + "' priority='" + priority + "'>\n");
            }

            for (Property property: properties) {
                xml.append(property.toString());
            }
            xml.append("</rule>\n");
            return xml.toString();
        }

        public static class Property {
            public enum Protocol {
                MAC("mac"), VLAN("vlan"), STP("stp"), IP("ip"), IPV4("ipv4"), IPV6("ipv6"), ARP("arp"), RARP("rarp"),
                TCP("tcp"), UDP("udp"), ICMP("icmp"), ICMPV6("icmpv6"), ALL("all"), TCP_IPV6("tcp-ipv6"),
                UDP_IPV6("udp-ipv6"), ALL_IPV6("all-ipv6");

                String _protocol;

                Protocol(String protocol) {
                    _protocol = protocol;
                }

                @Override
                public String toString() {
                    return _protocol;
                }
            }

            public enum State {
                NONE("NONE"), NEW("NEW"), ESTABLISHED("ESTABLISHED"), RELATED("RELATED"), INVALID("INVALID");

                String _state;

                State(String state) {
                    _state = state;
                }

                @Override
                public String toString() {
                    return _state;
                }
            }

            private Protocol protocol;
            private String srcmacaddr;
            private InetAddress srcipaddr;
            private String srcipmask;
            private InetAddress dstipaddr;
            private String dstipmask;
            private int srcportstart;
            private int srcportend;
            private int dstportstart;
            private int dstportend;
            private int type = -1;
            private int code = -1;
            private List<State> states = new ArrayList<>();

            public Property(Protocol protocol) {
                this.protocol = protocol;
            }

            public void setSrcmacaddr(String srcmacaddr) {
                this.srcmacaddr = srcmacaddr;
            }

            public void setSrcipaddr(InetAddress srcipaddr) {
                this.srcipaddr = srcipaddr;
            }

            public void setSrcipmask(String srcipmask) {
                this.srcipmask = srcipmask;
            }

            public void setDstipaddr(InetAddress dstipaddr) {
                this.dstipaddr = dstipaddr;
            }

            public void setDstipmask(String dstipmask) {
                this.dstipmask = dstipmask;
            }

            public void setSrcportstart(int srcportstart) {
                this.srcportstart = srcportstart;
            }

            public void setSrcportend(int srcportend) {
                this.srcportend = srcportend;
            }

            public void setDstportstart(int dstportstart) {
                this.dstportstart = dstportstart;
            }

            public void setDstportend(int dstportend) {
                this.dstportend = dstportend;
            }

            public void setType(int type) {
                this.type = type;
            }

            public void setCode(int code) {
                this.code = code;
            }

            public void addState(State state) {
                states.add(state);
            }

            @Override
            public String toString() {
                StringBuilder xml = new StringBuilder();

                xml.append("<" + protocol + " ");

                if (StringUtils.isNotBlank(srcmacaddr)) {
                    xml.append("srcmacaddr='" + srcmacaddr + "' ");
                }

                if (srcipaddr != null) {
                    xml.append("srcipaddr='" + srcipaddr.getHostAddress() + "' ");
                }

                if (StringUtils.isNotBlank(srcipmask)) {
                    xml.append("srcipmask='" + srcipmask + "' ");
                }

                if (dstipaddr != null) {
                    xml.append("dstipaddr='" + dstipaddr.getHostAddress() + "' ");
                }

                if (StringUtils.isNotBlank(dstipmask)) {
                    xml.append("dstipmask='" + dstipmask + "' ");
                }

                if (srcportstart > 0) {
                    xml.append("srcportstart='" + srcportstart + "' ");
                }
                if (srcportend > 0) {
                    xml.append("srcportend='" + srcportend + "' ");
                }

                if (dstportstart > 0) {
                    xml.append("dstportstart='" + dstportstart + "' ");
                }

                if (dstportend > 0) {
                    xml.append("dstportend='" + dstportend + "' ");
                }

                if (type >= 0) {
                    xml.append("type='" + type + "' ");
                }

                if (code >= 0) {
                    xml.append("code='" + code + "' ");
                }

                if (states.size() > 0) {
                    xml.append("state='" + StringUtils.join(states, ",") + "' ");
                }

                xml.append("/>\n");
                return xml.toString();
            }
        }
    }

    public static class FilterRef {
        public static class Parameter {
            private String name;
            private String value;

            public Parameter(String name, String value) {
                this.name = name;
                this.value = value;
            }

            @Override
            public String toString() {
                return new String("<parameter name='" + name + "' value='" + value + "'/>\n");
            }
        }

        private String filter;
        private List<Parameter> parameters = new ArrayList<>();

        public FilterRef(String filter) {
            this.filter = filter;
        }

        public String getFilter() {
            return filter;
        }

        public void addParameter(Parameter parameter) {
            parameters.add(parameter);
        }

        @Override
        public String toString() {
            StringBuilder xml = new StringBuilder();

            xml.append("<filterref filter='" + filter + "'>\n");
            for (Parameter parameter: parameters) {
                xml.append(parameter.toString());
            }
            xml.append("</filterref>\n");
            return xml.toString();
        }

    }
}
