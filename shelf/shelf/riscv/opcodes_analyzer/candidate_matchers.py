from shelf.lib.utils.match_utils import ConsecutiveMatcher
from shelf.riscv.opcodes_analyzer.relocation_candidates import LuiLdCandidate


class ConsecutiveLuiLdMatcher(ConsecutiveMatcher):
    def __init__(self):
        super(ConsecutiveLuiLdMatcher, self).__init__(
            number_of_matches=2
        )

    def _match(self, index, obj):
        """
            Trying to get:
            0x400086715c    <SHELF:strlen +0x28>:	lui	a4,0x72
            0x4000867160    <SHELF:strlen +0x2c>:	ld	a1,-1992(a4)
            consecutive instructions
        """
        if index == 0 and obj.mnemonic == 'lui':
            return True
        elif index == 1 and 'ld' in obj.mnemonic:
            return True

        return False

    def add_matches(self, matches):
        candidate = LuiLdCandidate(
            matches[0],
            matches[1]
        )
        if candidate.is_valid():
            self.matches.append(candidate)

