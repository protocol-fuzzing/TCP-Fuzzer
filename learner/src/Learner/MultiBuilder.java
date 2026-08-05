package Learner;

import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.AlphabetBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.AlphabetBuilderStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.alphabet.xml.AlphabetSerializerXml;
import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.statistics.MealyMachineWrapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapper;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.SULWrapperStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.mapper.context.ExecutionContext;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzer;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerComposerStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.StateFuzzerStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerClientConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerConfigBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerEnabler;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.core.config.StateFuzzerServerConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DiffTester;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DiffTesterBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DiffTesterEnabler;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DiffTesterStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.config.DiffTesterConfig;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.config.DiffTesterConfigBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.config.DiffTesterConfigStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunner;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunnerBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.TestRunnerStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.core.config.TestRunnerEnabler;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbe;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbeBuilder;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.TimingProbeStandard;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.testrunner.timingprobe.config.TimingProbeEnabler;

public class MultiBuilder
    implements
        StateFuzzerConfigBuilder,
        StateFuzzerBuilder<MealyMachineWrapper<TCPInput, TCPOutput>>,
        TestRunnerBuilder,
        TimingProbeBuilder,
        DiffTesterConfigBuilder,
        DiffTesterBuilder {

    // , TCPOutput, AlphabetPojoXmlImpl need to be implemented
    protected AlphabetBuilder<TCPInput> alphabetBuilder =
        new AlphabetBuilderStandard<>(
            new AlphabetSerializerXml<TCPInput, TCPAlphabetPojoXml>(
                TCPInput.class,
                TCPAlphabetPojoXml.class
            )
        );

    // ExecutionContextImpl, SulBuilderImpl need to be implemented
    protected SULBuilder<
        TCPInput,
        TCPOutput,
        ExecutionContext<TCPInput, TCPOutput, String>
    > sulBuilder = new TCPSULBuilder();
    protected SULWrapper<
        TCPInput,
        TCPOutput,
        ExecutionContext<TCPInput, TCPOutput, String>
    > sulWrapper = new SULWrapperStandard<>();

    // SulClientConfigImpl and MapperConfigImpl need to be implemented
    @Override
    public StateFuzzerClientConfig buildClientConfig() {
        return new TCPStateFuzzerClientConfig(new TCPSULClientConfig());
    }

    // SulServerConfigImpl (and MapperConfigImpl) need to be implemented
    @Override
    public StateFuzzerServerConfig buildServerConfig() {
        return new TCPStateFuzzerServerConfig(new TCPSULServerConfig());
    }

    @Override
    public DiffTesterConfig buildConfig() {
        return new DiffTesterConfigStandard();
    }

    @Override
    public DiffTester build(DiffTesterEnabler diffTesterEnabler) {
        return new DiffTesterStandard<>(diffTesterEnabler, alphabetBuilder);
    }

    @Override
    public StateFuzzer<MealyMachineWrapper<TCPInput, TCPOutput>> build(
        StateFuzzerEnabler stateFuzzerEnabler
    ) {
        return new StateFuzzerStandard<>(
            new StateFuzzerComposerStandard<>(
                stateFuzzerEnabler,
                alphabetBuilder,
                sulBuilder
            ).initialize()
        );
    }

    @Override
    public TestRunner build(TestRunnerEnabler testRunnerEnabler) {
        return new TestRunnerStandard<>(
            testRunnerEnabler,
            alphabetBuilder,
            sulBuilder
        ).initialize();
    }

    @Override
    public TimingProbe build(TimingProbeEnabler timingProbeEnabler) {
        return new TimingProbeStandard<>(
            timingProbeEnabler,
            alphabetBuilder,
            sulBuilder
        ).initialize();
    }
}
