/*
 * Copyright 2014 Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.ifwd;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.onlab.packet.Ethernet;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import com.google.common.collect.Streams;

import fr.pantheosorbonne.cri.HLFacade;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent
 * framework.
 */
@Component(immediate = true)
public class IntentReactiveForwarding {

	private final Logger log = getLogger(getClass());

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected CoreService coreService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected TopologyService topologyService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected PacketService packetService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected IntentService intentService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected HostService hostService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected FlowRuleService flowRuleService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected FlowObjectiveService flowObjectiveService;

	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	protected DeviceService deviceService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

	private ReactivePacketProcessor processor = new ReactivePacketProcessor();
	private ApplicationId appId;

	private static final int DROP_RULE_TIMEOUT = 300;

	private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
			IntentState.WITHDRAWING, IntentState.WITHDRAW_REQ);
	final static Collection<HostId> blockedHosts = new HashSet<>();
	final static Collection<String> blockedHostPairs = new HashSet<>();

	@Activate
	public void activate() {

//		try {
//			ClientApp.main(new String[0]);
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			log.error("bc failed", e);
//
//		}

		appId = coreService.registerApplication("org.onosproject.ifwd");

		packetService.addProcessor(processor, PacketProcessor.director(2));

		TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
		selector.matchEthType(Ethernet.TYPE_IPV4);
		packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
		HLFacade facade = HLFacade.getDefaultBuilder()//
				.withDeviceService(deviceService)//
				.withFlowRuleSerice(flowRuleService)//
				.withIntentService(intentService)//
				.withTopologyService(topologyService)//
				.withHostService(hostService)//
				.withEdgePortService(edgePortService)
				.build();

		Runnable r = () -> {
			while (true) {

				try {
					Thread.sleep(500);
					facade.dump();

				} catch (Throwable t) {
					log.error("oups", t);
				}

			}
		};
		new Thread(r).start();

		new Thread(new Runnable() {
			@Override
			public void run() {

				while (true) {

					Set<String> lines = new HashSet<>();
					try (BufferedReader reader = new BufferedReader(new FileReader("/home/nherbaut/intent.txt"))) {
						reader.lines().peek(l -> lines.add(l)).forEach(new Consumer<String>() {
							@Override
							public void accept(String s) {
								String[] items = s.split(" ");
								switch (items[0]) {
								case "block":
									if (blockedHosts.add(HostId.hostId(items[1]))) {
										logToFile("block " + HostId.hostId(items[1]));
										removeIntentsForHost(HostId.hostId(items[1]));
									}
									break;
								case "allow":
									if (blockedHosts.remove(HostId.hostId(items[1]))) {
										logToFile("unblock " + HostId.hostId(items[1]));
									}
									break;
								case "block-from-to":
									if (blockedHostPairs.add(HostId.hostId(items[1]) + "" + HostId.hostId(items[2]))) {
										logToFile("block from " + HostId.hostId(items[1]) + " to "
												+ HostId.hostId(items[2]));
										removeIntentsForHostPair(HostId.hostId(items[1]),HostId.hostId(items[2]));
										
									}
									break;
								default:
									// fallthrough
								}
							}
						});

						// remove all blocks that are not on the file anymore
						Set<HostId> newlyAllowedHosts = blockedHosts.stream()
								.filter(l -> !lines.contains("block " + l.toString())).collect(Collectors.toSet());
						newlyAllowedHosts.stream().forEach(h -> logToFile("unblock " + h));
						blockedHosts.removeAll(newlyAllowedHosts);
						
						Set<String> pairsToRemove = new HashSet<String>();
						for(String pair : blockedHostPairs) {
							boolean found=false;
							String h1=pair.substring(0,22);
							String h2=pair.substring(22);
							for(String line : lines) {
								if(line.equals("block-from-to "+h1+" "+h2)) {
									found=true;
									break;
								}
							}
							
							if(!found) {
								pairsToRemove.add(pair);
							}
							
						}
						
						blockedHostPairs.removeAll(pairsToRemove);

						Thread.sleep(10);

					} catch (IOException | InterruptedException fnf) {
						fnf.printStackTrace();
					}

				}

			}

			private void removeIntentsForHost(HostId hostId) {

				Set<HostToHostIntent> intentsToDiscard = Streams.stream(intentService.getIntents())
						.filter(i -> i instanceof HostToHostIntent) //
						.map(i -> (HostToHostIntent) i) //
						.filter(i -> i.one().equals(hostId) || i.two().equals(hostId)) //
						.collect(Collectors.toUnmodifiableSet()); //
					intentsToDiscard.parallelStream().peek(i -> log.warn("removing intent from {} to {}", i.one(), i.two()))
						.forEach(intent -> intentService.withdraw(intent));

			}
			
			private void removeIntentsForHostPair(HostId src, HostId dst) {

				Set<HostToHostIntent> intentsToDiscard = Streams.stream(intentService.getIntents())
						.filter(i -> i instanceof HostToHostIntent) //
						.map(i -> (HostToHostIntent) i) //
						.filter(i -> i.one().equals(src) || i.two().equals(dst)) //
						.collect(Collectors.toUnmodifiableSet()); //
					intentsToDiscard.parallelStream().peek(i -> log.warn("removing intent from {} to {}", i.one(), i.two()))
						.forEach(intent -> intentService.withdraw(intent));

			}
		}).start();

		log.info("Started");
	}

	private void logToFile(String log) {
		try (Writer w = new FileWriter("/home/nherbaut/intents-logs.txt", true)) {
			w.write(System.currentTimeMillis() + "\t" + log + "\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Deactivate
	public void deactivate() {
		packetService.removeProcessor(processor);
		processor = null;
		log.info("Stopped");
	}

	/**
	 * Packet processor responsible for forwarding packets along their paths.
	 */
	private class ReactivePacketProcessor implements PacketProcessor {

		@Override
		public void process(PacketContext context) {
			// Stop processing if the packet has been handled, since we
			// can't do any more to it.
			if (context.isHandled()) {
				return;
			}
			InboundPacket pkt = context.inPacket();
			Ethernet ethPkt = pkt.parsed();

			if (ethPkt == null) {
				return;
			}

			HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
			HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());

			if (blockedHosts.contains(srcId) || blockedHosts.contains(dstId)) {
				drop(context);
				return;
			}

			if (blockedHostPairs.contains(srcId + "" + dstId) || blockedHostPairs.contains(dstId + "" + srcId)) {
				drop(context);
				return;
			}

			// Do we know who this is for? If not, flood and bail.
			Host dst = hostService.getHost(dstId);
			if (dst == null) {
				flood(context);
				return;
			}

			// Otherwise forward and be done with it.
			setUpConnectivity(context, srcId, dstId);
			forwardPacketToDst(context, dst);
		}

	}

	private void drop(PacketContext context) {
		context.block();
	}

	// Floods the specified packet if permissible.
	private void flood(PacketContext context) {
		if (topologyService.isBroadcastPoint(topologyService.currentTopology(), context.inPacket().receivedFrom())) {
			packetOut(context, PortNumber.FLOOD);
		} else {
			context.block();
		}
	}

	// Sends a packet out the specified port.
	private void packetOut(PacketContext context, PortNumber portNumber) {
		context.treatmentBuilder().setOutput(portNumber);
		context.send();
	}

	private void forwardPacketToDst(PacketContext context, Host dst) {
		TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
		OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(), treatment,
				context.inPacket().unparsed());
		packetService.emit(packet);
		log.info("sending packet: {}", packet);
	}

	// Install a rule forwarding the packet to the specified port.
	private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
		TrafficSelector selector = DefaultTrafficSelector.emptySelector();
		TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

		Key key;
		if (srcId.toString().compareTo(dstId.toString()) < 0) {
			key = Key.of(srcId.toString() + dstId.toString(), appId);
		} else {
			key = Key.of(dstId.toString() + srcId.toString(), appId);
		}

		HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
		// TODO handle the FAILED state
		if (intent != null) {
			if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
				HostToHostIntent hostIntent = HostToHostIntent.builder().appId(appId).key(key).one(srcId).two(dstId)
						.selector(selector).treatment(treatment).build();

				intentService.submit(hostIntent);
			} else if (intentService.getIntentState(key) == IntentState.FAILED) {

				TrafficSelector objectiveSelector = DefaultTrafficSelector.builder().matchEthSrc(srcId.mac())
						.matchEthDst(dstId.mac()).build();

				TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder().drop().build();

				ForwardingObjective objective = DefaultForwardingObjective.builder().withSelector(objectiveSelector)
						.withTreatment(dropTreatment).fromApp(appId).withPriority(intent.priority() - 1)
						.makeTemporary(DROP_RULE_TIMEOUT).withFlag(ForwardingObjective.Flag.VERSATILE).add();

				flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
			}

		} else if (intent == null) {
			HostToHostIntent hostIntent = HostToHostIntent.builder().appId(appId).key(key).one(srcId).two(dstId)
					.selector(selector).treatment(treatment).build();

			intentService.submit(hostIntent);
		}

	}

}
