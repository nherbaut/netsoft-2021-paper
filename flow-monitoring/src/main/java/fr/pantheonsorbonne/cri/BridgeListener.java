package fr.pantheonsorbonne.cri;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.BlockingQueue;

public class BridgeListener implements Runnable {

	final String br;
	final BlockingQueue<Event> col;

	public BridgeListener(String br, BlockingQueue<Event> col) {
		this.br = br;
		this.col = col;
	}

	@Override
	public void run() {

		ProcessBuilder pb = new ProcessBuilder("sudo", "ovs-ofctl", "monitor", this.br, "watch:!own");
		
		pb.redirectErrorStream(true);
		try {
			Process p = pb.start();

			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

			for (String line = reader.readLine(); (line = reader.readLine()) != null;) {
				if (line.contains("event=")) {
					String[] lineComponents = line.split(" ");
					Event e = OFUnMarshaller.unMarshall(Event.class, lineComponents);
					col.put(e);

				} // drop non-event flow
			}

			p.waitFor();
			reader.close();
			System.out.println("done!");

		} catch (IOException | InterruptedException e) {
			throw new RuntimeException(e);
		}

	}
}
