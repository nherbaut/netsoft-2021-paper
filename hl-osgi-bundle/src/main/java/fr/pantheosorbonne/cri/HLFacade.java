package fr.pantheosorbonne.cri;

import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Identities;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import com.google.common.util.concurrent.AsyncCallable;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;

public class HLFacade {

    interface Function<T, R> {

        public String getTransactionName();

        public Contract getContract(Network network);

        public String[] getArgs(T t);

        public R deserializeResponse(byte[] data);

    }

    public static Function<FlowImpl, FlowImpl> submitFlow = new Function<FlowImpl, FlowImpl>() {

        @Override
        public String getTransactionName() {
            return "logflow";
        }

        @Override
        public Contract getContract(Network network) {
            return network.getContract("papercontract", "fr.pantheonsorbonne.cri");

        }

        @Override
        public String[] getArgs(FlowImpl t) {
            return new String[] { t.device, "" + t.timestamp, t.event, "" + t.table, "" + t.icmp, t.reason, "" + t.arp,
                    "" + t.in_port, t.dl_src, t.dl_dst, t.arp_spa, t.arp_tpa, "" + t.arp_op, "" + t.nw_tos,
                    "" + t.icmp_type, "" + t.icmp_code, t.actions };
        }

        @Override
        public FlowImpl deserializeResponse(byte[] data) {
            return FlowImpl.deserialize(data);
        }

    };

    public static <T, R> Future<R> submit(Function<T, R> f, T t) {

        return Futures.submitAsync(new AsyncCallable<R>() {

            @Override
            public ListenableFuture<R> call() throws Exception {
                ConnectionMaterial conMat = null;
                try {
                    conMat = conMats.take();

                    Contract contract = f.getContract(conMat.network);
                    byte[] data = contract.submitTransaction(f.getTransactionName(), f.getArgs(t));
                    // System.out.println("Received from fabric :" + new String(data, "UTF-8"));
                    return Futures.immediateFuture(f.deserializeResponse(data));
                } catch (Throwable t) {
                    t.printStackTrace();
                    throw t;
                } finally {

                    try {
                        if (conMat != null) {
                            conMats.put(conMat);
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                        return Futures.immediateFailedFuture(e);
                    }
                }

            }
        }, exec);

    }

    private final static int executor_count;
    private final static BlockingQueue<ConnectionMaterial> conMats;
    private final static ExecutorService exec;

    static class ConnectionMaterial implements Closeable {

        private Gateway gateway;
        private Network network;

        public ConnectionMaterial(Gateway.Builder builder) {
            gateway = builder.connect();
            network = gateway.getNetwork("mychannel");
        }

        @Override
        public void close() throws IOException {
            gateway.close();
        }

    }

    public static final Function<Void, String> listAllFlows = new Function<Void, String>() {

        @Override
        public String getTransactionName() {
            return "listAllFlows";
        }

        @Override
        public Contract getContract(Network network) {
            return network.getContract("papercontract", "fr.pantheonsorbonne.cri");
        }

        @Override
        public String[] getArgs(Void t) {
            return new String[0];
        }

        @Override
        public String deserializeResponse(byte[] data) {

            return new String(data);
        }

    };
    private final static Path connectionProfile;
    public static final Function<String, String> listFlowForDevice = new Function<String, String>() {

        @Override
        public String getTransactionName() {
            return "listFlowsForDevice";
        }

        @Override
        public Contract getContract(Network network) {
            return network.getContract("papercontract", "fr.pantheonsorbonne.cri");
        }

        @Override
        public String[] getArgs(String t) {
            return new String[] { t };
        }

        @Override
        public String deserializeResponse(byte[] data) {
            return new String(data);
        }

    };

    static {

        executor_count = Integer.valueOf(System.getenv().getOrDefault("executor_count", "24"));
        conMats = new LinkedBlockingDeque<ConnectionMaterial>();
        exec = Executors.newFixedThreadPool(executor_count);

        connectionProfile = Path.of(
                System.getenv().getOrDefault("connectionProfile","/home/nherbaut/workspace/fabric/fabric-samples/commercial-paper/organization/magnetocorp/gateway/connection-org2.yaml"));

        try {
            Wallet wallet = Wallets.newInMemoryWallet();

            Path credentialPath = Paths.get(
                    System.getenv().getOrDefault("credentialPath", "/home/nherbaut/workspace/fabric/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp"));

            Path certificatePath = credentialPath.resolve(Paths.get("signcerts", "User1@org2.example.com-cert.pem"));
            Path privateKeyPath = credentialPath.resolve(Paths.get("keystore", "priv_sk"));

            X509Certificate certificate = readX509Certificate(certificatePath);
            PrivateKey privateKey = getPrivateKey(privateKeyPath);

            Identity identity = Identities.newX509Identity("Org2MSP", certificate, privateKey);

            String identityLabel = "User1@org2.example.com";
            wallet.put(identityLabel, identity);

            Gateway.Builder builder = Gateway.createBuilder();

            String userName = "User1@org2.example.com";

            builder.identity(wallet, userName).networkConfig(connectionProfile).discovery(false);

            Executor exec = Executors.newFixedThreadPool(executor_count);
            IntStream.range(0, executor_count).forEach(i -> exec.execute(new Runnable() {

                @Override
                public void run() {

                    try {

                        ConnectionMaterial mat = new ConnectionMaterial(builder);
                        conMats.put(mat);

                    } catch (Throwable t) {
                        t.printStackTrace();

                    }

                }

            }));

            // exec.awaitTermination(10, TimeUnit.SECONDS);

            System.out.println("terminating building thread");

        } catch (IOException | CertificateException | InvalidKeyException e) {
            e.printStackTrace();

        }

    }

    public static RSAPublicKey readPublicKey(File file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        }
    }

    static PrivateKey getPrivateKeyFromBytes(byte[] data)
            throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Reader pemReader = new StringReader(new String(data));

        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }

        PrivateKey privateKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getPrivateKey(pemPair);

        return privateKey;
    }

    private static X509Certificate readX509Certificate(final Path certificatePath)
            throws IOException, CertificateException {
        try (Reader certificateReader = Files.newBufferedReader(certificatePath, StandardCharsets.UTF_8)) {
            return Identities.readX509Certificate(certificateReader);
        }
    }

    private static PrivateKey getPrivateKey(final Path privateKeyPath) throws IOException, InvalidKeyException {
        try (Reader privateKeyReader = Files.newBufferedReader(privateKeyPath, StandardCharsets.UTF_8)) {
            return Identities.readPrivateKey(privateKeyReader);
        }
    }

}
