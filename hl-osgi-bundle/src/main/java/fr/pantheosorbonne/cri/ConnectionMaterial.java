package fr.pantheosorbonne.cri;

import java.io.Closeable;
import java.io.IOException;

import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;

class ConnectionMaterial implements Closeable {

    private Gateway gateway;
    private Network network;

    public ConnectionMaterial(Gateway.Builder builder, String contractName) {
        gateway = builder.connect();
        network = gateway.getNetwork("mychannel");

    }

    @Override
    public void close() throws IOException {
        gateway.close();
    }

    public Gateway getGateway() {
        return gateway;
    }

    public Network getNetwork() {
        return network;
    }

    public void setGateway(Gateway gateway) {
        this.gateway = gateway;
    }

    public void setNetwork(Network network) {
        this.network = network;
    }

}