package fr.pantheonsorbonne.cri;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;

import org.buildobjects.process.ProcBuilder;

import fr.pantheosorbonne.cri.FlowImpl;
import fr.pantheosorbonne.cri.HLFacade;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) throws IOException, InterruptedException {

        BlockingQueue<FlowImpl> col = new LinkedBlockingQueue<FlowImpl>();
        Collection<Future<FlowImpl>> futures = new CopyOnWriteArrayList<Future<FlowImpl>>();
        Arrays.stream(ProcBuilder.run("sudo", "ovs-vsctl", "list-br").split("\n"))//
                .map(br -> new BridgeListener(br, col))//
                .forEach(r -> {
                    System.out.println("starting listening thread on " + r.br);
                    new Thread(r).start();
                });

        FlowImpl e;

        new Thread(new Runnable() {

            @Override
            public void run() {
                while (true) {
                    long doneFlows = futures.stream().filter(f -> f.isDone()).count();
                    System.out.println(String.format("%d\t%d", doneFlows, futures.size()));
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }

            }
        }).start();
        while (true) {
            e = col.take();
            futures.add(HLFacade.submit(HLFacade.submitFlow, e));
        }

    }
}
