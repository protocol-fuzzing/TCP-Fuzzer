package Learner;

import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.config.LearnerConfigStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULClientConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerClientConfigStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerConfigStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeConfigStandard;

public class TCPStateFuzzerClientConfig
    extends StateFuzzerClientConfigStandard {

    public TCPStateFuzzerClientConfig(SULClientConfig sulClientConfig) {
        super(
            new LearnerConfigStandard(),
            sulClientConfig,
            new TestRunnerConfigStandard(),
            new TimingProbeConfigStandard()
        );
    }
}
