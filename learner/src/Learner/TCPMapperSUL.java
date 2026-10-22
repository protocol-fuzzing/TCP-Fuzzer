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
        this.startSeq = (
            this.startSeq + ThreadLocalRandom.current().nextInt(10000, 30000)
        ) & 0xFFFFFFFFL; // wrap around to stay within 32-bit unsigned range
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
            String inputPayload = in.getPayload();
            socketSul.send(in.getFlags());
            socketSul.send(String.valueOf(in.getSeq()));
            socketSul.send(String.valueOf(in.getAck()));
            output = socketSul.sendAndRecv(inputPayload); // An empty string means this input has no payload.

            // Sending RST closes our side of the connection, even though the
            // server does not answer it.
            if (in.getFlags().contains("R")) {
                context.getState().setNeedsNewIsn(true);
            }
        }

        if (output.equals("timeout") || output.startsWith("timeout")) {
            return new TCPOutput(output);
        } else {
            // Split the returned packet (it has format "seq,ack,flags,payloadHex,dpiRule").
            String[] split = output.split(",", 5);
            String outputSeq = split[0];
            String outputAck = split[1];
            String outputFlags = split[2];
            String outputPayloadHex = split.length > 3 ? split[3] : "";
            String outputDpiRule = split.length > 4 ? split[4] : "";

            int outputPayloadSize = 0;

            if (outputPayloadHex != null && !outputPayloadHex.isEmpty()) {
                // Every byte is represented by two hexadecimal characters.
                outputPayloadSize = outputPayloadHex.length() / 2;
            }

            // The final component of a composite output such as
            // "A|PA_DATA_1" describes the segment whose seq, ack and payload
            // the mapper returned.
            String finalResponseLabel = outputFlags.substring(
                outputFlags.lastIndexOf('|') + 1
            );
            String finalResponseFlags = finalResponseLabel.replaceFirst("_.*$", ""); // "PA_ACK2_D1" -> "PA"

            if (outputFlags.contains("R")) {
                // The server dropped the connection. Keep seq and ack as they
                // are: the next input is sent as if we had missed the RST.
                // Only a new SYN gets a new ISN.
                context.getState().setNeedsNewIsn(true);
            } else {
                // The response ACK becomes our next sequence number.
                context.getState().setSeq(Long.parseLong(outputAck));

                // Payload bytes consume TCP sequence numbers.
                int ackIncrement = outputPayloadSize;

                // SYN and FIN each consume one TCP sequence number. Only the
                // final segment counts: an earlier SYN or FIN in the label is
                // already included in the final segment's seq.
                if (finalResponseFlags.contains("S") || finalResponseFlags.contains("F")) {
                    ackIncrement += 1;
                }

                context.getState().setAck((Long.parseLong(outputSeq) + ackIncrement) & 0xFFFFFFFFL); 
            }

            String outputLabel = outputFlags;

            // Keep compatibility with mapper outputs that do not already
            // contain a payload annotation.
            if (
                outputPayloadSize > 0
                && !finalResponseLabel.matches(".*_D\\d+$")
            ) {
                outputLabel += "_D" + outputPayloadSize;
            }

            if (outputDpiRule != null && !outputDpiRule.isEmpty()) {
                outputLabel += "," + outputDpiRule;
            }

            return new TCPOutput(
                outputLabel,
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
