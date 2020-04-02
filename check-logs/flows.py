import re

class FlowLog:
    def __init__(self, timestamp, deviceId):
        self.timestamp = timestamp
        self.deviceId = deviceId


class EthPacket:
    def __init__(self, src, dst):

        self.src = ":".join(re.findall("([0-9a-fA-F]{2})",src))
        self.dst = ":".join(re.findall("([0-9a-fA-F]{2})",dst))


class OutputFlowLog(FlowLog):
    def __init__(self, timestamp, deviceId, dl_src, dl_dst, output_action,to_host):
        super().__init__(timestamp, deviceId)
        self.dl_src = dl_src
        self.dl_dst = dl_dst
        self.output_action = output_action
        self.to_host=to_host

    def __str__(self):
        return "%s-%s -> %s" % (self.dl_src,self.dl_dst,self.output_action)

    def get_next_device(self,dl_src,dl_dst):
        if self.dl_src==dl_src and self.dl_dst==dl_dst:
            return self.output_action
        elif self.dl_src==dl_src and self.dl_dst is None:
            return self.output_action

        else:
            return None


class DropFlowLog(FlowLog):
    def __init__(self, timestamp, deviceId, dl_src, dl_dst, output_action):
        super().__init__(timestamp, deviceId)
        self.dl_src = dl_src
        self.dl_dst = dl_dst
        self.output_action = output_action

    def __str__(self):
        ret = ""
        if (self.dl_src is not None):
            ret += "src= %s " % self.dl_src
        if (self.dl_dst is not None):
            ret += "dst= %s " % self.dl_dst
        ret += " DROP"
        return ret

    def isDropping(self, packet):
        same_src = (self.dl_src == packet.src)
        same_dst = (self.dl_dst == packet.dst)

        if self.dl_src is None:
            return same_dst
        if self.dl_dst is None:
            return same_src
        else:
            return same_dst and same_src
