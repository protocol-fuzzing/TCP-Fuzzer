package Learner;

import com.github.protocolfuzzing.protocolstatefuzzer.components.learner.config.LearnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULClientConfig;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerClientConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerConfigStandard;
import com.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeConfigStandard;

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
