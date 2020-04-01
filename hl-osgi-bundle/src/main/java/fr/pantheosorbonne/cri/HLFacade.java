package fr.pantheosorbonne.cri;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.FileWriter;
import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.stream.Collectors;

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
import org.onosproject.net.topology.TopologyGraph;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import com.google.common.base.Strings;
import com.google.common.collect.Streams;

public class HLFacade {

	private FileWriter flowWriter;
	private FileWriter intentWriter;
	private FileWriter debugWriter;

	private FlowRuleService frs;
	private DeviceService deviceService;
	private IntentService intentService;
	private TopologyService topoService;
	private EdgePortService edgePortService;
	private FileWriter hostsWriter;
	public HostService hostService;;

	public static HLFacadeBuilder getDefaultBuilder() {
		return new HLFacadeBuilder();
	}

	static public class HLFacadeBuilder {
		private HLFacade facade;

		public HLFacadeBuilder() {
			facade = new HLFacade();
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

		public HLFacade build() {
			if (this.facade.topoService == null || this.facade.deviceService == null
					|| (this.facade.intentService == null && this.facade.frs == null)) {
				throw new RuntimeException(
						"Failed to build HLFacade, you should have 1 Device service and 1 intent service or flow service");
			}
			return this.facade;
		}

	}

	private static final Logger log = getLogger(HLFacade.class);

	private HLFacade() {
		try {
			flowWriter = new FileWriter("/home/nherbaut/flow-logs", true);
			intentWriter = new FileWriter("/home/nherbaut/intent-logs", true);
			hostsWriter = new FileWriter("/home/nherbaut/host-logs", true);
			debugWriter = new FileWriter("/home/nherbaut/debug-logs", true);

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void dump() {
		try {
			long now = System.currentTimeMillis();
			for (Device d : deviceService.getDevices(Type.SWITCH)) {
				for (FlowEntry fe : frs.getFlowEntries(d.id())) {
					writeFlow(fe, now);
				}

			}
			flowWriter.flush();
			if (intentService != null) {
				for (Intent intent : intentService.getIntents()) {
					writeIntent(intent, now);
				}
			}
			intentWriter.flush();

			for (Host h : hostService.getHosts()) {
				writeHost(h, now);
			}
			hostsWriter.flush();
		} catch (IOException e) {
			log.error("failed to write log", e);
		}

	}

	private void writeHost(Host h, long now) {
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
			hostsWriter.write(sb.toString());
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

	private void writeDebug(String s) {
		try {
			debugWriter.write(s + "\n");
			debugWriter.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void writeFlow(FlowRule rule, long timestamp) {
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
					.peek(v -> writeDebug("available vertex:" + v.toString()))
					.filter(v -> v.deviceId().equals(rule.deviceId()))//
					.peek(v -> writeDebug("matching vertex with device id" + v.toString()))
					.map(v -> graph.getEdgesFrom(v).stream()//
							.peek(e -> writeDebug("ports from edge " + e.link().src().port().toString()))
							.filter(e -> e.link().src().port().equals(o.port()))//
							.peek(e -> writeDebug("matching ports from edge " + e.link().src().port().toString()))
							.map(e -> e.dst().deviceId())//
							.peek(d -> writeDebug("matching next device " + d))//
							.findFirst().orElseThrow(() -> {
								return new NoSuchElementException("failed to find ");
							}))//
					.findFirst()//
					.orElseThrow();

			writeDebug(rule.treatment().allInstructions().stream().map(i -> i.type().toString())
					.collect(Collectors.toSet()).stream().collect(Collectors.joining(",")) + "\n");

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

				sendTo = "mac:" + Streams.stream(edgePortService.getEdgePoints(rule.deviceId()))
						.peek(c -> log.warn(c.port() + " @@ " + c.toString()))//
						.filter(c -> c.port().name().equals(pn.name())).map(cp -> hostService.getConnectedHosts(cp))
						.findFirst().orElseThrow().stream().findFirst().orElseThrow().mac().toString();

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
			flowWriter.append(builder.toString());
			flowWriter.flush();
		} catch (IOException | NoSuchElementException e) {
			log.warn("failed to write log", e);
		}
	}

	public void writeIntent(Intent intent, long timestamp) {
		try {
			StringBuilder builder = new StringBuilder();

			if (intent instanceof HostToHostIntent) {
				var h2h = (HostToHostIntent) intent;
				builder.append(timestamp).append("\t");
				builder.append(intentService.getIntentState(intent.key())).append("\t");
				builder.append(h2h.resources().stream().map(Object::toString).collect(Collectors.joining("\t")));
				intentWriter.write(builder.append("\n").toString());
			}

		} catch (IOException e) {
			log.error("failed to write log", e);
		}
	}
}
