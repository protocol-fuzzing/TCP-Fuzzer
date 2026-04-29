package Learner;

import com.github.protocolfuzzing.protocolstatefuzzer.components.sul.core.config.SULServerConfigStandard;
import com.beust.jcommander.ParametersDelegate;

public class TCPSULServerConfig
    extends SULServerConfigStandard
    implements TCPMapperConfigProvider {

    @ParametersDelegate
    private TCPMapperConfig tcpMapperConfig;

    public TCPSULServerConfig() {
        tcpMapperConfig = new TCPMapperConfig();
    }

    @Override
    public TCPMapperConfig getTCPMapperConfig() {
        return tcpMapperConfig;
    }
}
