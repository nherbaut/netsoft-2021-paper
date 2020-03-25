package fr.pantheonsorbonne.cri;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;

import fr.pantheosorbonne.cri.FlowImpl;

public class BridgeListener implements Runnable {

    final String br;
    final BlockingQueue<FlowImpl> col;

    public BridgeListener(String br, BlockingQueue<FlowImpl> col) {
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
                    Instant now = Instant.now();
                    String[] lineComponents = line.split(" ");
                    FlowImpl e = OFUnMarshaller.unMarshall(FlowImpl.class, lineComponents);
                    e.setDevice(br);
                    e.setTimestamp(now.getEpochSecond() + 1e-9 * now.getNano());
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
