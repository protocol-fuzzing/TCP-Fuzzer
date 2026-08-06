package Learner;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.concurrent.ThreadLocalRandom;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSUL;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULAdapter;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.DynamicPortProvider;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.sulwrappers.ProcessHandler;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;
import io.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;

public class TCPMapperSUL
    implements
        AbstractSUL<
            TCPInput,
            TCPOutput,
            ExecutionContext<TCPInput, TCPOutput, String>
        > {

    private SocketMapperSUL socketSul;

    /** Stores the constructor parameter. */
    protected SULConfig sulConfig;

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
    protected SULAdapter sulAdapter;

    public <T extends SULConfig & TCPMapperConfigProvider> TCPMapperSUL(
        T sulConfig,
        CleanupTasks cleanupTasks
    ) throws UnknownHostException, IOException {
        // copied from the commit before the introduction of generics
        // -------------------------------------------------------------------
        this.sulConfig = sulConfig;
        this.cleanupTasks = cleanupTasks;
        // mapper and sulAdapter will be provided in subclasses
        this.mapper = new TCPMapper();
        this.sulAdapter = new TCPSULAdapter();
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

        socketSul = new SocketMapperSUL(sock);
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
            String inputPayload = "";
            if (in.getName().contains("P")){
                inputPayload = "x" ;
            }
            socketSul.send(in.getName());
            socketSul.send(String.valueOf(in.getSeq()));
            socketSul.send(String.valueOf(in.getAck()));
            output = socketSul.sendAndRecv(inputPayload); // without 'P' flag, payload is empty.
        }

         if (output.equals("timeout")) {
            return new TCPOutput("timeout");
        } else {
            // Split the returned packet (it has format "seq,ack,flags,payloadHex,dpiRule").
            String[] split = output.split(",", 5);
            String outputSeq = split[0];
            String outputAck = split[1];
            String outputFlags = split[2];
            String outputPayloadHex = split.length > 3 ? split[3] : "";
            String outputDpiRule = split.length > 4 ? split[4] : "";

            if (outputFlags.contains("R")) {
                // If reset is recevied we reset sequence and acknowledgement numbers.                
                startSeq += ThreadLocalRandom.current().nextInt(10000, 30000);
                context.getState().setSeq(startSeq);
                context.getState().setAck(startSeq + 1);
            } else {
                // We update the seq number to the output's ack number 
                // regardless if the output contains a 'A' flag.
                context.getState().setSeq(Long.parseLong(outputAck));

                int ackIncrement = 0; 
                int payloadLength = 0;

                // If the output contains a payload (indicated by the presence of 'P' flag), we increment the ack number by the payload length.
                if (outputPayloadHex != null && !outputPayloadHex.isEmpty() && outputFlags.contains("P")) {
                    payloadLength = outputPayloadHex.length() / 2; // Each byte is represented by 2 hex characters.
                    ackIncrement += payloadLength;
                }
                
                // If the output contains a 'S' or 'F' flag, we increment the ack number.
                if (outputFlags.contains("S") || outputFlags.contains("F")) {
                    ackIncrement += 1;
                }
                context.getState().setAck(Long.parseLong(outputSeq) + ackIncrement);
            }

            String outputFlagsandDpiRule = outputFlags;
            if (outputDpiRule != null && !outputDpiRule.isEmpty()) {
                outputFlagsandDpiRule = outputFlags + "," + outputDpiRule;
            }

            return new TCPOutput(
                outputFlagsandDpiRule,
                Long.parseLong(outputSeq),
                Long.parseLong(outputAck)
            );
        }
    }

    @Override
    public SULConfig getSULConfig() {
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
    public SULAdapter getSULAdapter() {
        return sulAdapter;
    }
}
