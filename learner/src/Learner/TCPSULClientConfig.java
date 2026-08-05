package Learner;

import io.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULClientConfigStandard;
import com.beust.jcommander.ParametersDelegate;

public class TCPSULClientConfig
    extends SULClientConfigStandard
    implements TCPMapperConfigProvider {

    @ParametersDelegate
    private TCPMapperConfig tcpMapperConfig;

    public TCPSULClientConfig() {
        tcpMapperConfig = new TCPMapperConfig();
    }

    @Override
    public TCPMapperConfig getTCPMapperConfig() {
        return tcpMapperConfig;
    }
}
