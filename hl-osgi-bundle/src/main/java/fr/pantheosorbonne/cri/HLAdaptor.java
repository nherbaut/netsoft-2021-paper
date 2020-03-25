package fr.pantheosorbonne.cri;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.Device.Type;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.Intent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.topology.TopologyEdge;
import org.onosproject.net.topology.TopologyGraph;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import com.google.common.base.Strings;

public class HLAdaptor {

    private FlowRuleService frs;
    private DeviceService deviceService;
    private IntentService intentService;
    private TopologyService topoService;
    private EdgePortService edgePortService;

    public HostService hostService;;

    public static HLFacadeBuilder getDefaultBuilder() {
        return new HLFacadeBuilder();
    }

    static public class HLFacadeBuilder {
        private HLAdaptor facade;

        public HLFacadeBuilder() {
            facade = new HLAdaptor();
        }

        public HLFacadeBuilder withFlowRuleSerice(FlowRuleService service) {
            this.facade.frs = service;
            return this;
        }

        public HLFacadeBuilder withDeviceService(DeviceService service) {
            this.facade.deviceService = service;
            return this;
        }

        public HLFacadeBuilder withIntentService(IntentService intentService) {
            this.facade.intentService = intentService;
            return this;
        }

        public HLFacadeBuilder withTopologyService(TopologyService service) {
            this.facade.topoService = service;
            return this;
        }

        public HLFacadeBuilder withHostService(HostService service) {
            this.facade.hostService = service;
            return this;
        }

        public HLFacadeBuilder withEdgePortService(EdgePortService service) {
            this.facade.edgePortService = service;
            return this;
        }

        public HLAdaptor build() {
            if (this.facade.topoService == null || this.facade.deviceService == null
                    || (this.facade.intentService == null && this.facade.frs == null)) {
                throw new RuntimeException(
                        "Failed to build HLFacade, you should have 1 Device service and 1 intent service or flow service");
            }
            return this.facade;
        }

    }

    private static final Logger log = getLogger(HLAdaptor.class);

    private HLAdaptor() {

    }

    public void dump() {

        long now = System.currentTimeMillis();

        try {
            var nowStr = "" + now;
            String f1 = nowStr.substring(0, 6);
            String f2 = nowStr.substring(6, 9);
            String f3 = nowStr.substring(9);

            var dst = Paths.get("/home/nherbaut/logs/", f1, f2, f3);
            Files.createDirectories(Paths.get("/home/nherbaut/logs/", f1, f2, f3));
            var flowWriter = new BufferedWriter(new FileWriter(Paths.get(dst.toString(), "flow.log").toString(), true));
            var intentWriter = new BufferedWriter(
                    new FileWriter(Paths.get(dst.toString(), "intent.log").toString(), true));
            var hostsWriter = new BufferedWriter(
                    new FileWriter(Paths.get(dst.toString(), "hosts.log").toString(), true));
            var topologyWriter = new BufferedWriter(
                    new FileWriter(Paths.get(dst.toString(), "topology.log").toString(), true));

            for (Device d : deviceService.getDevices(Type.SWITCH)) {
                for (FlowEntry fe : frs.getFlowEntries(d.id())) {
                    writeFlow(fe, now, flowWriter);
                }

            }
            flowWriter.flush();
            flowWriter.close();
            if (intentService != null) {
                for (Intent intent : intentService.getIntents()) {
                    writeIntent(intent, now, intentWriter);
                }
            }
            intentWriter.flush();
            intentWriter.close();
            for (Host h : hostService.getHosts()) {
                writeHost(h, now, hostsWriter);
            }
            hostsWriter.flush();
            hostsWriter.close();

            writeTopo(topoService.getGraph(topoService.currentTopology()).getEdges(), topologyWriter);
            topologyWriter.flush();
            topologyWriter.close();

        } catch (IOException e) {
            log.error("failed to write log", e);
        }

    }

    private void writeTopo(Set<TopologyEdge> edges, BufferedWriter topologyWriter) {
        for (TopologyEdge e : edges) {
            try {
                topologyWriter.append(e.src().deviceId().toString()).append("\t").append(e.dst().deviceId().toString())
                        .append("\n");
            } catch (IOException e1) {
                log.warn("failed to write log", e1);
            }
        }

    }

    private void writeHost(Host h, long now, Writer w) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(now).append("\t");
            sb.append(h.mac().toString()).append("\t");
            for (Device d : deviceService.getDevices(Type.SWITCH)) {
                if (hostService.getConnectedHosts(d.id()).contains(h)) {
                    sb.append(d.id().toString());
                    break;
                }
            }
            sb.append("\n");
            w.write(sb.toString());
        } catch (IOException e) {
            log.warn("failed to write log", e);
        }

    }

    private static String citerionTypeToStr(Criterion.Type type) {
        if (type.equals(Criterion.Type.ETH_DST)) {
            return "to:";
        } else if (type.equals(Criterion.Type.ETH_SRC)) {
            return "from:";
        } else {
            return "na:";
        }
    }

    private void writeDebug(String s, Writer w) {
        try {
            w.write(s + "\n");
            w.flush();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void writeFlow(FlowRule rule, long timestamp, Writer w) {
        TopologyGraph graph = topoService.getGraph(topoService.currentTopology());

        StringBuilder builder = new StringBuilder();
        try {

            String matches = rule.selector().criteria().stream()//
                    .filter(c -> c.getClass().equals(EthCriterion.class))//
                    .map(c -> (EthCriterion) c)//
                    .map(c -> citerionTypeToStr(c.type()) + c.mac())//
                    .collect(Collectors.joining(","));//
            if (Strings.isNullOrEmpty(matches)) {
                return;
            }

            Function<OutputInstruction, DeviceId> mapToNextDevice = o -> graph.getVertexes().stream()//
                    // .peek(v -> writeDebug("available vertex:" + v.toString(), w))
                    .filter(v -> v.deviceId().equals(rule.deviceId()))//
                    // .peek(v -> writeDebug("matching vertex with device id" + v.toString(), w))
                    .map(v -> graph.getEdgesFrom(v).stream()//
                            // .peek(e -> writeDebug("ports from edge " + e.link().src().port().toString(),
                            // w))
                            .filter(e -> e.link().src().port().equals(o.port()))//
                            // .peek(e -> writeDebug("matching ports from edge " +
                            // e.link().src().port().toString(), w))
                            .map(e -> e.dst().deviceId())//
                            // .peek(d -> writeDebug("matching next device " + d, w))//
                            .findFirst().orElseThrow(() -> {
                                return new NoSuchElementException("failed to find ");
                            }))//
                    .findFirst()//
                    .orElseThrow();

            // writeDebug(rule.treatment().allInstructions().stream().map(i ->
            // i.type().toString()).collect(Collectors.toSet()).stream().collect(Collectors.joining(","))
            // + "\n", w);

            String sendTo = null;
            try {
                // try if the next target is a device
                sendTo = rule.treatment().immediate().stream()//
                        .filter(t -> t instanceof OutputInstruction)//
                        .map(t -> (OutputInstruction) t).map(mapToNextDevice).map(d -> d.toString())
                        .collect(Collectors.joining(","));
            } catch (NoSuchElementException nse) {
                PortNumber pn = rule.treatment().immediate().stream()//
                        .filter(t -> t instanceof OutputInstruction)//
                        .map(t -> ((OutputInstruction) t).port()).findFirst().orElseThrow();

                sendTo = "mac:";
                outter: for (ConnectPoint cp : edgePortService.getEdgePoints(rule.deviceId())) {
                    if (cp.port().name().equals(pn.name())) {
                        for (Host h : hostService.getConnectedHosts(cp)) {
                            sendTo += h.mac().toString();
                            break outter;
                        }
                    }
                }

            }

            if (Strings.isNullOrEmpty(sendTo)) {
                sendTo = "DROP";
            } else {
                sendTo = "OUTPUT:" + sendTo;
            }

            builder.append(timestamp);
            builder.append("\t");
            builder.append(rule.deviceId());
            builder.append("\t");
            builder.append(matches);
            builder.append("\t");
            builder.append(sendTo);
            builder.append("\n");
            w.append(builder.toString());
            w.flush();
        } catch (IOException | NoSuchElementException e) {
            log.warn("failed to write log", e);
        }
    }

    public void writeIntent(Intent intent, long timestamp, Writer w) {
        try {
            StringBuilder builder = new StringBuilder();

            if (intent instanceof HostToHostIntent) {
                var h2h = (HostToHostIntent) intent;
                builder.append(timestamp).append("\t");
                builder.append(intentService.getIntentState(intent.key())).append("\t");
                builder.append(h2h.resources().stream().map(Object::toString).collect(Collectors.joining("\t")));
                w.write(builder.append("\n").toString());
            }

        } catch (IOException e) {
            log.error("failed to write log", e);
        }
    }
}
