package org.onosproject.fwd;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.Device;
import org.onosproject.net.HostId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flowobjective.DefaultFilteringObjective;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.slf4j.Logger;

public class SecurityConnectivityPolicyChangeConsummer implements Consumer<java.nio.file.Path> {

	private final Logger log = getLogger(getClass());
	private final Collection<HostId> blockedHosts;
	private final Collection<String> blockedHostPairs;
	private final ApplicationId appId;
	private final DeviceService deviceService;
	private final FlowObjectiveService flowObjectiveService;

	public SecurityConnectivityPolicyChangeConsummer(final Collection<HostId> blockedHosts,
			final Collection<String> blockedHostPairs, final ApplicationId appId, final DeviceService deviceService,
			final FlowObjectiveService flowObjectiveService) {

		this.blockedHostPairs = blockedHostPairs;
		this.blockedHosts = blockedHosts;
		this.appId = appId;
		this.deviceService = deviceService;
		this.flowObjectiveService = flowObjectiveService;

	}

	private void logToFile(String log) {
		try (Writer w = new FileWriter("/home/nherbaut/nointents-logs.txt", true)) {
			w.write(System.currentTimeMillis() + "\t" + log + "\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void blockingRule(HostId from, HostId to, boolean remove) {
		try {

			FilteringObjective.Builder filteringObjectiveBuilder = DefaultFilteringObjective.builder().deny()
					.fromApp(appId).withPriority(50000).makePermanent();

			Criterion criteria = null;
			if (from != null) {
				criteria = Criteria.matchEthSrc(from.mac());
				filteringObjectiveBuilder = filteringObjectiveBuilder.addCondition(criteria);
			}
			if (to != null) {
				criteria = Criteria.matchEthDst(to.mac());
				filteringObjectiveBuilder = filteringObjectiveBuilder.addCondition(criteria);
			}

			filteringObjectiveBuilder.withKey(criteria);

			if (remove) {
				log.warn("blocking from=" + from + " to=" + to + " with key " + criteria);
			} else {
				log.warn("releasing from=" + from + " to=" + to + " with key " + criteria);
			}

			FilteringObjective objective;
			if (remove) {
				objective = filteringObjectiveBuilder.remove();
			} else {
				objective = filteringObjectiveBuilder.add();
			}

			for (Device d : deviceService.getDevices(Device.Type.SWITCH)) {
				flowObjectiveService.apply(d.id(), objective);

			}
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

	@Override
	public void accept(Path t) {

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
								blockingRule(HostId.hostId(items[1]), null, false);
								blockingRule(null, HostId.hostId(items[1]), false);

							}
							break;

						case "block-from-to":
							if (blockedHostPairs.add(HostId.hostId(items[1]) + ";" + HostId.hostId(items[2]))) {
								logToFile("block from " + HostId.hostId(items[1]) + " to " + HostId.hostId(items[2]));

								blockingRule(HostId.hostId(items[2]), HostId.hostId(items[1]), false);
								blockingRule(HostId.hostId(items[1]), HostId.hostId(items[2]), false);
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
				newlyAllowedHosts.stream().peek(h -> logToFile("unblock " + h)).peek(h -> blockingRule(h, null, true))
						.forEach(h -> blockingRule(null, h, true));
				blockedHosts.removeAll(newlyAllowedHosts);

				Predicate<String[]> p1 = l -> lines.contains("block-from-to " + l[0] + " " + l[1]);
				Predicate<String[]> p2 = l -> lines.contains("block-from-to " + l[1] + " " + l[0]);

				Set<String[]> newlyAllowedHostPair = blockedHostPairs.stream().map(h -> h.split(";"))
						.filter(Predicate.not(p1).and(Predicate.not(p2))).collect(Collectors.toSet());
				for (String[] hosts : newlyAllowedHostPair) {

					{
						var a1 = hosts[0] + ";" + hosts[1];
						blockingRule(HostId.hostId(hosts[0]), HostId.hostId(hosts[1]), true);
						blockedHostPairs.remove(a1);
					}
					{
						var a1 = hosts[1] + ";" + hosts[0];
						blockingRule(HostId.hostId(hosts[1]), HostId.hostId(hosts[0]), true);
						blockedHostPairs.remove(a1);
					}

				}
				Thread.sleep(3000);

			} catch (IOException | InterruptedException fnf) {
				fnf.printStackTrace();
			}
		}

	}

}
