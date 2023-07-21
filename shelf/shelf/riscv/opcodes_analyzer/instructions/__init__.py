import re


class BaseInstruction(object):
    def __init__(self, capstone_ins):
        self.capstone_ins = capstone_ins


class RiscvGenericLoadStoreInstruction(BaseInstruction):
    def __init__(self, capstone_ins):
        super(RiscvGenericLoadStoreInstruction, self).__init__(capstone_ins=capstone_ins)
        self.source_register = self.capstone_ins.op_str.split(",")[0]
        pattern = r'\((.*?)\)'
        matches = re.findall(pattern, self.capstone_ins.op_str)
        if not matches:
            self.destination_register = None
        else:
            self.destination_register = matches[0]


class LuiInstruction(RiscvGenericLoadStoreInstruction):
    pass


class LdInstruction(RiscvGenericLoadStoreInstruction):
    pass
