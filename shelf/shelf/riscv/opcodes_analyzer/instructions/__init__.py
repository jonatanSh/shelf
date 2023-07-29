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
    def __init__(self, capstone_ins):
        super(LuiInstruction, self).__init__(capstone_ins=capstone_ins)
        try:
            self.immediate = int(self.capstone_ins.op_str.split(",")[-1], 16) << 12
        except Exception as e:
            self.immediate = None


class LdInstruction(RiscvGenericLoadStoreInstruction):
    def __init__(self, capstone_ins):
        super(LdInstruction, self).__init__(capstone_ins=capstone_ins)
        try:
            pattern = r'[a-z0-9]+,\s*([-+]?\d+)\('
            offset_part = re.findall(pattern,self.capstone_ins.op_str)
            self.offset = int(offset_part[0], 10)
        except Exception as e:
            self.offset = None