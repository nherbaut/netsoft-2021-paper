/*
SPDX-License-Identifier: Apache-2.0
*/

package fr.pantheosorbonne.cri;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.Future;

public class FeedData {

    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
    }

    public static void main(String[] args) throws Exception {

        Instant now = Instant.now();

        Collection<Future<FlowImpl>> flows = new ArrayList<>();

        for (int i = 0; i < 100000; i++) {
            FlowImpl f = new FlowImpl().setEvent("dummy_event").setDevice("s1").setTimestamp(i);
            flows.add(HLFacade.submit(HLFacade.submitFlow, f));
        }

        boolean init = false;
        while (flows.stream().filter(future -> !future.isDone()).findAny().isPresent()) {
            Thread.sleep(1000);
            long doneCount = flows.stream().filter(future -> future.isDone()).count();
            if (doneCount > 0) {
                if (!init) {
                    init = true;
                    now = Instant.now();
                }
                long duration = Instant.now().minus(now.getEpochSecond(), ChronoUnit.SECONDS).getEpochSecond();
                System.out.println(String.format("%d;%d;%f", duration, doneCount, (float) doneCount / duration));
            }

        }

    }

}
