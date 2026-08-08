'''
    Used to instantiate all other components via the TOMLParser module.
'''

# Modules which will be built
from sender import Sender
from learnerSocket import LearnerSocket
from SUTSocket import SUTSocket

# Parsing the arguments for those modules
from tomlParser import TOMLParser


class Builder(object):
    config = {}

    def __init__(self, configFile):
        self.config = TOMLParser(configFile).getConfig()
    
    def buildSender(self):
        """Builds TCP packet sender"""
        dpi_config = self.config.get("DPI", {})
        dpi_enabled = dpi_config.get("enabled", False)

        dpi_alerts_file = None
        dpi_wait_time = 0.05

        if dpi_enabled:
            dpi_alerts_file = dpi_config.get("alerts_file", "/var/log/snort/alert_fast.txt",)

            dpi_wait_time = dpi_config.get("waittime", 0.05,)

        return Sender(
            serverIP=self.config["SUT"]["ip"],
            serverPort=self.config["SUT"]["port"],
            waitTime=self.config["SUT"]["waittime"],
            dpiAlertsFile=dpi_alerts_file,
            dpiWaitTime=dpi_wait_time,
        )
    
    # builds the actionSender as a wrapper over the original sender component
    def buildSUTSocket(self, sender):
        values = self.argParser.parseArguments(args.actionSenderArguments, "actionSender")
        values.update({"sender" : sender})
        actionSender = SUTSocket(**values)
        return actionSender
    
    def buildLearnerSocket(self):
        """Builds the socket which connects the sender to the learner"""
        
        return LearnerSocket(self.config["Learner"]["ip"], self.config["Learner"]["port"])
    
