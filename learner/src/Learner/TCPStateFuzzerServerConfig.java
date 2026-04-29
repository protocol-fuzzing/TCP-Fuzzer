package Learner;

import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.config.LearnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULServerConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerServerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeConfigStandard;

public class TCPStateFuzzerServerConfig
    extends StateFuzzerServerConfigStandard {

    public TCPStateFuzzerServerConfig(SULServerConfig sulServerConfig) {
        super(
            new LearnerConfigStandard(),
            sulServerConfig,
            new TestRunnerConfigStandard(),
            new TimingProbeConfigStandard()
        );
    }
}
