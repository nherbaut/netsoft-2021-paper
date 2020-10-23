package fr.pantheonsorbonne.cri;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.buildobjects.process.ProcBuilder;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) throws IOException, InterruptedException {

		BlockingQueue<Event> col = new LinkedBlockingQueue<Event>();

		Arrays.stream(ProcBuilder.run("sudo", "ovs-vsctl", "list-br").split("\n"))//
				.map(br -> new BridgeListener(br, col))//
				.forEach(r -> {
					System.out.println("starting listening thread on " + r.br);
					new Thread(r).start();
				});

		Event e;
		while (true) {
			e = col.take();
			System.out.println(e);
		}

	}
}
