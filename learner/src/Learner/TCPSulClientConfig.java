package Learner;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULClientConfigStandard;
import com.beust.jcommander.ParametersDelegate;

public class TCPSulClientConfig
    extends SULClientConfigStandard
    implements TCPMapperConfigProvider {

    @ParametersDelegate
    private TCPMapperConfig sshMapperConfig;

    public TCPSulClientConfig() {
        sshMapperConfig = new TCPMapperConfig();
    }

    @Override
    public TCPMapperConfig getTCPMapperConfig() {
        return sshMapperConfig;
    }
}
