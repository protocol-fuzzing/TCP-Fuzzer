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
        String output;
        /*
        Reset does not need seq and ack numbers  
        The "reset" special case is for the control reset 
        (telling the mapper to change ports), not for a TCP RST packet.
         */
        if (in.getName().equals("reset")) {
            output = socketSul.sendAndRecv(in.getName());
        } else {
            socketSul.send(in.getName());
            socketSul.send(String.valueOf(in.getSeq()));
            socketSul.send(String.valueOf(in.getAck()));
            output = socketSul.sendAndRecv("");
        }

        if (output.equals("timeout")) {
            return new TCPOutput("timeout");
        } else {
            // Split the returned packet (it has format "seq,ack,flags")
            String[] split = output.split(",");
            String outputFlags = split[2];
            String outputAck = split[1];
            String outputSeq = split[0];

            if (outputFlags.contains("R")) {
                // If reset is recevied we reset sequence and acknowledgement numbers                
                startSeq += ThreadLocalRandom.current().nextInt(10000, 30000);
                context.getState().setSeq(startSeq);
                context.getState().setAck(startSeq + 1);
            } 
            // we update the seq number to the output's ack number
            // regardless if output contains a 'A' flag
            context.getState().setSeq(Long.parseLong(outputAck));

            // if the output contains a 'S' or 'F' flag, we increment the ack number by 1
            if (outputFlags.contains("S") || outputFlags.contains("F")) {
                context.getState().setAck(Long.parseLong(outputSeq) + 1);
            } else {
                // otherwise we set the ack number to the output's seq number
                context.getState().setAck(Long.parseLong(outputSeq));
            }

            return new TCPOutput(
                outputFlags,
                Long.parseLong(outputSeq),
                Long.parseLong(outputAck)
            );
        }
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
