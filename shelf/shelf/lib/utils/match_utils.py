class ConsecutiveMatcher(object):
    # For more references on how to use this take a look at riscv64 opcodes relocation
    def __init__(self, number_of_matches):
        """
        :param number_of_matches: Number of required consecutive objects
        """
        self.matches = []
        self.current_match_stack = set()
        self.number_of_matches = number_of_matches

    def _match(self, index, obj):
        """
        Return True if matched or false
        :param index: the index of the match
        :param obj: the object to match
        :return:
        """
        raise NotImplementedError()

    def match(self, obj):
        if len(self.current_match_stack) == self.number_of_matches:
            self.add_matches(self.current_match_stack)
            self.current_match_stack = set()

        if self._match(len(self.current_match_stack), obj):
            self.current_match_stack.add(obj)
        else:
            stack_not_empty = len(self.current_match_stack) != 0
            self.current_match_stack = set()
            if stack_not_empty:
                self.match(obj)  # Enter rematch

    def get_matches(self):
        return self.matches

    def add_matches(self, matches):
        self.matches.append(matches)
