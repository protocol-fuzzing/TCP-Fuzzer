package Learner;

import Learner.TCPExecutionContext;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.AbstractInputXml;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;

public class TCPInput
    extends AbstractInputXml<
        TCPOutput,
        String,
        ExecutionContext<TCPInput, TCPOutput, String>
    > {

    private long seq;
    private long ack;
    private final String flags;
    private final int payloadSize;
    private final String payloadPattern;

    public TCPInput(String name, String flags, int payloadSize, String payloadPattern) {
        super(name);
        if (payloadSize < 0) {
            throw new IllegalArgumentException("Payload size cannot be negative.");
        }
        if (payloadPattern == null || payloadPattern.isEmpty()) {
            throw new IllegalArgumentException("Payload pattern cannot be empty.");
        }
        this.flags = flags;
        this.payloadSize = payloadSize;
        this.payloadPattern = payloadPattern;
    }

    public long getSeq() {
        return this.seq;
    }

    public long getAck() {
        return this.ack;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public void setAck(long ack) {
        this.ack = ack;
    }

    public String getFlags() {
        return this.flags;
    }

    public int getPayloadSize() {
        return this.payloadSize;
    }

    public boolean hasPayload() {
        return this.payloadSize > 0;
    }

    public String getPayload() {
        if (!hasPayload()) {
            return "";
        }
        return payloadPattern.repeat(payloadSize);
    }

    @Override
    public void preSendUpdate(
        ExecutionContext<TCPInput, TCPOutput, String> context
    ) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String generateProtocolMessage(
        ExecutionContext<TCPInput, TCPOutput, String> context
    ) {
        System.out.println("From generateProtocolMessage!");
        throw new UnsupportedOperationException();
    }

    @Override
    public void postSendUpdate(
        ExecutionContext<TCPInput, TCPOutput, String> context
    ) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void postReceiveUpdate(
        TCPOutput output,
        OutputChecker<TCPOutput> outputChecker,
        ExecutionContext<TCPInput, TCPOutput, String> context
    ) {
        throw new UnsupportedOperationException();
    }

        @Override
        public String toString() {
            return this.name;
        }
    }
