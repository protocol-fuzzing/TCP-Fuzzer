package Learner;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.ThreadLocalRandom;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSul;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SulAdapter;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SulConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.DynamicPortProvider;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.ProcessHandler;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;
import com.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;

public class TCPMapperSul
    implements
        AbstractSul<
            TCPInput,
            TCPOutput,
            ExecutionContext<TCPInput, TCPOutput, String>
        > {

    private SocketMapperSul socketSul;

    /** Stores the constructor parameter. */
    protected SulConfig sulConfig;

    /** Stores the constructor parameter. */
    protected CleanupTasks cleanupTasks;

    /** Stores the provided dynamic port provider. */
    protected DynamicPortProvider dynamicPortProvider;

    /** Stores the current execution */
    protected TCPExecutionContext context;

    /** Stores the starting sequence number for the next sequence **/
    protected long startSeq = ThreadLocalRandom.current().nextLong(10000, 30000);

    /** Stores the Mapper instance. */
    protected TCPMapper mapper;

    /** Stores the SulAdapter instance. */
    protected SulAdapter sulAdapter;

    public <T extends SulConfig & TCPMapperConfigProvider> TCPMapperSul(
        T sulConfig,
        CleanupTasks cleanupTasks
    ) throws UnknownHostException, IOException {
        // copied from the commit before the introduction of generics
        // -------------------------------------------------------------------
        this.sulConfig = sulConfig;
        this.cleanupTasks = cleanupTasks;
        // mapper and sulAdapter will be provided in subclasses
        this.mapper = new TCPMapper();
        this.sulAdapter = new TCPSulAdapter();
        // -------------------------------------------------------------------

        String mapperAddress = sulConfig
            .getTCPMapperConfig()
            .getMapperAddress();
        String[] addressSplit = mapperAddress.split("\\:");
        if (addressSplit.length != 2) {
            throw new MapperException(
                "Invalid mapper host, expected hostAddress:hostPort"
            );
        }
        String mapperIpAddress = addressSplit[0];
        Integer mapperPort = Integer.valueOf(addressSplit[1]);
        if (sulConfig.getTCPMapperConfig().getMapperCommand() != null) {
            MapperProcessHandler handler = new MapperProcessHandler(
                sulConfig.getTCPMapperConfig().getMapperCommand(),
                sulConfig.getTCPMapperConfig().getMapperStartWait()
            );
            handler.launchProcess();
        }
        Socket sock = new Socket(mapperIpAddress, mapperPort);
        cleanupTasks.submit(
            new Runnable() {
                @Override
                public void run() {
                    if (socketSul != null) {
                        socketSul.reset();
                    }
                    try {
                        sock.close();
                    } catch (IOException e) {
                        throw new MapperException(e);
                    }
                }
            }
        );

        socketSul = new SocketMapperSul(sock);
    }

    // Before each query we create a blank context
    @Override
    public void pre() {
        socketSul.reset();
        if(this.startSeq > Long.MAX_VALUE - 100000) {
            this.startSeq = ThreadLocalRandom.current().nextLong(10000, 30000);
        }
        this.startSeq = this.startSeq + ThreadLocalRandom.current().nextInt(10000, 30000);
        this.context = new TCPExecutionContext(new TCPState(this.startSeq, 0));
    }

    @Override
    public void post() {}

    private static class MapperProcessHandler extends ProcessHandler {

        protected MapperProcessHandler(String command, long startWait) {
            super(command);
        }
    }

    @Override
    public TCPOutput step(TCPInput in) {
        this.mapper.updateInput(in, this.context);

        final String name = in.getName();
        final boolean outHasS = name.contains("S");
        final boolean outHasF = name.contains("F");
        final boolean outHasP = name.contains("P");  //P means 1 byte of payload

        // reset input does not need seq and ack numbers
        if ("reset".equals(name)) {
            socketSul.sendAndRecv(name);
            // Reset local tracking
            startSeq += ThreadLocalRandom.current().nextInt(10000, 30000);
            context.getState().setSeq(startSeq);
            context.getState().setAck(0);
            return new TCPOutput("reset");
        }

        final long seqBefore = in.getSeq();
        final long ackBefore = in.getAck();
        socketSul.send(name);
        socketSul.send(String.valueOf(seqBefore));
        socketSul.send(String.valueOf(ackBefore));
        final String output = socketSul.sendAndRecv("");
        // How much SEQ space this outgoing segment would consume
        // S and F each consume 1, P also consume 1 
        final long outConsume = (outHasS ? 1 : 0) + (outHasF ? 1 : 0) + (outHasP ? 1 : 0);
        final long nextSeqCandidate = seqBefore + outConsume;

        //timeout: peer did not respond window so do not advance local seq/ack
        if ("timeout".equals(output)) {
            return new TCPOutput("timeout");
        }

        // Returned packet format: "seq,ack,flags"
        String[] split = output.split(",");
        final long peerSeq = Long.parseLong(split[0]);
        final long peerAck = Long.parseLong(split[1]);
        final String peerFlags = split[2];

        // RST received, reset local tracking
        if (peerFlags.contains("R")) {
        startSeq += ThreadLocalRandom.current().nextInt(10000, 30000);
        context.getState().setSeq(startSeq);
        context.getState().setAck(0);
        return new TCPOutput(peerFlags, peerSeq, peerAck);
        }  

        // Update local ACK (= next expected from server)
        long newLocalAck = peerSeq;
        if (peerFlags.contains("S")) newLocalAck += 1;
        if (peerFlags.contains("F")) newLocalAck += 1;
        if (peerFlags.contains("P")) newLocalAck += 1;
        context.getState().setAck(newLocalAck);

        // Update local SEQ without drift
        // Advance the SEQ only if the server ACKs it.
        // If server sends a corrective ACK (peerAck < nextSeqCandidate), resync to peerAck.
        if (peerAck >= nextSeqCandidate) {
            context.getState().setSeq(nextSeqCandidate);
        } else {
            context.getState().setSeq(peerAck);
        }

        return new TCPOutput(peerFlags, peerSeq, peerAck);
    }

    @Override
    public SulConfig getSulConfig() {
        return sulConfig;
    }

    @Override
    public CleanupTasks getCleanupTasks() {
        return cleanupTasks;
    }

    @Override
    public void setDynamicPortProvider(
        DynamicPortProvider dynamicPortProvider
    ) {
        this.dynamicPortProvider = dynamicPortProvider;
    }

    @Override
    public DynamicPortProvider getDynamicPortProvider() {
        return dynamicPortProvider;
    }

    @Override
    public Mapper<
        TCPInput,
        TCPOutput,
        ExecutionContext<TCPInput, TCPOutput, String>
    > getMapper() {
        return (Mapper) mapper;
    }

    @Override
    public SulAdapter getSulAdapter() {
        return sulAdapter;
    }
}
