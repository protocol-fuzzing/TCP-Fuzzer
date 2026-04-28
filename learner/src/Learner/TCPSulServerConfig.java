package Learner;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULServerConfigStandard;
import com.beust.jcommander.ParametersDelegate;

public class TCPSulServerConfig
    extends SULServerConfigStandard
    implements TCPMapperConfigProvider {

    @ParametersDelegate
    private TCPMapperConfig sshMapperConfig;

    public TCPSulServerConfig() {
        sshMapperConfig = new TCPMapperConfig();
    }

    @Override
    public TCPMapperConfig getTCPMapperConfig() {
        return sshMapperConfig;
    }
}
