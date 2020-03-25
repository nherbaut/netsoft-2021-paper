package fr.pantheosorbonne.cri;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class GetFlows {

    public static void main(String[] args) throws InterruptedException, ExecutionException {
        Future<String> data = HLFacade.submit(HLFacade.listAllFlows, null);

        while (!data.isDone()) {
            Thread.sleep(100);

        }

        System.out.println(data.get());

    }

}
