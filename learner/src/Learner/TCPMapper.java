package Learner;

import Learner.TCPExecutionContext;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.Mapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.abstractsymbols.OutputChecker;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.config.MapperConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;

public class TCPMapper
    implements Mapper<TCPInput, TCPOutput, TCPExecutionContext> {

    @Override
    public TCPOutput execute(TCPInput input, TCPExecutionContext context) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException(
            "Unimplemented method 'execute'"
        );
    }

    /**
     * How far the initial sequence number moves for a new connection after a
     * reset. Our SYNs have no window scale option, so a window is at most
     * 65535 and the old and new sequence numbers cannot overlap.
     */
    static final long NEW_ISN_STEP = 0x20000L;

    /**
     * Takes a TCPInput and updates it's state according to the execution context
     * @param input the input to update
     * @param context the current execution context
     */
    public void updateInput(TCPInput input, TCPExecutionContext context) {
        TCPState state = context.getState();
        String flags = input.getFlags();
        // A SYN after a reset opens a new connection, so it gets a new ISN.
        // Other inputs keep the old numbers.
        if (state.needsNewIsn() && flags.contains("S") && !flags.contains("A")) {
            state.setSeq((state.getSeq() + NEW_ISN_STEP) & 0xFFFFFFFFL);
            state.setNeedsNewIsn(false);
        }
        input.setSeq(state.getSeq());
        input.setAck(state.getAck());
    }

    @Override
    public MapperConfig getMapperConfig() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException(
            "Unimplemented method 'getMapperConfig'"
        );
    }

    @Override
    public OutputBuilder<TCPOutput> getOutputBuilder() {
        return new TCPOutputBuilder();
    }

    @Override
    public OutputChecker<TCPOutput> getOutputChecker() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException(
            "Unimplemented method 'getOutputChecker'"
        );
    }
}
