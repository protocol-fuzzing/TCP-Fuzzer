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

    public TCPInput(String name) {
        super(name);
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
        // Display P and PA with a data label in dot outputs.
        if (this.name.equals("P") || this.name.equals("PA")) {
            return this.name + "+data";
        }
        return this.name;
    }
}
