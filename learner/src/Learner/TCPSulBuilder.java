package Learner;

import java.io.IOException;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.AbstractSUL;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULBuilder;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapper;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapperStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;
import com.github.protocolfuzzing.protocolstatefuzzer.utils.CleanupTasks;

public class TCPSulBuilder
    implements
        SULBuilder<
            TCPInput,
            TCPOutput,
            ExecutionContext<TCPInput, TCPOutput, String>
        > {

	@Override
	public AbstractSUL<TCPInput, TCPOutput, ExecutionContext<TCPInput, TCPOutput, String>> buildSUL(SULConfig sulConfig,
			CleanupTasks cleanupTasks) {
		try {
            AbstractSUL<
                TCPInput,
                TCPOutput,
                ExecutionContext<TCPInput, TCPOutput, String>
            > tcpSulConfig = null;
            if (sulConfig.isFuzzingClient()) {
                tcpSulConfig = new TCPMapperSul(
                    (TCPSulClientConfig) sulConfig,
                    cleanupTasks
                );
                return tcpSulConfig;
            } else {
                tcpSulConfig = new TCPMapperSul(
                    (TCPSulServerConfig) sulConfig,
                    cleanupTasks
                );
                return tcpSulConfig;
            }
        } catch (IOException e) {
            throw new MapperException("Error creating TCPMapperSul", e);
        }
		
	}

	@Override
	public SULWrapper<TCPInput, TCPOutput, ExecutionContext<TCPInput, TCPOutput, String>> buildWrapper() {
		return new SULWrapperStandard<>();
	}

//	@Override
//	public AbstractSUL<TCPInput, TCPOutput, ExecutionContext<TCPInput, TCPOutput, String>> build(SULConfig sulConfig,
//			CleanupTasks cleanupTasks) {
//		// TODO Auto-generated method stub
//		return null;
//	}
}
