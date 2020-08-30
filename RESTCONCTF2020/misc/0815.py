#!/usr/bin/env python3

"""Interpreter for the 0815 esolang."""

# Standard library imports.
from enum import Enum
from sys import stdin, argv

# A signed 64-bit register.
FULL_BITWIDTH = 0xffffffffffffffff
SIGNED_BITWIDTH = 0x7fffffffffffffff
class Register:
    def __init__(self, val):
        self.value = val

    @property
    def value(self):
        return (self._val if 0 <= self._val <= SIGNED_BITWIDTH else
                self._val - FULL_BITWIDTH - 1)
    @value.setter
    def value(self, val):
        self._val = int(val) & FULL_BITWIDTH


# Interpreter states.
InterpreterStates = Enum('InterpreterStates',
                         'AWAITING_INSTRUCTION '
                         'GOT_INSTRUCTION '
                         'INSIDE_PARAMETER '
                         'DONE')

# The interpreter itself.
NEED_PARAM = '<}^#'
OPTIONAL_PARAM = '@&'
NO_PARAM = 'xX|!%$~=?>{+-*/'
INSTRUCTIONS = NEED_PARAM + OPTIONAL_PARAM + NO_PARAM
DELIMIT_PARAM = ':'
class Interpreter0815:
    def __init__(self, program):
        self.program = program
        self.pos = 0

        self.queue = []
        self.x = Register(0)
        self.y = Register(0)
        self.z = Register(0)
        self.labels = {}

        self.state = InterpreterStates.AWAITING_INSTRUCTION

        self.instructions = {'<': self.move,
                             'x': self.swap,
                             'X': self.swap,
                             '}': self.label,
                             '|': self.input_number,
                             '!': self.input_ascii,
                             '%': self.print_number,
                             '$': self.print_ascii,
                             '~': self.roll_left,
                             '=': self.roll_right,
                             '^': self.jump_if_not_zero,
                             '#': self.jump_if_zero,
                             '?': self.clear,
                             '>': self.enqueue,
                             '{': self.dequeue,
                             '@': self.roll_queue_left,
                             '&': self.roll_queue_right,
                             '+': self.add,
                             '-': self.subtract,
                             '*': self.multiply,
                             '/': self.divide}

    def run(self):
        """Run the program until it terminates."""
        while self.state != InterpreterStates.DONE:
            try:
                self.step()
            except KeyboardInterrupt:
                self.state = InterpreterStates.DONE
        print()

    def step(self):
        """Read and execute a single instruction."""
        if self.state == InterpreterStates.DONE:
            return
        elif self.pos >= len(self.program):
            self.state = InterpreterStates.DONE
            return

        assert self.state == InterpreterStates.AWAITING_INSTRUCTION
        previous_state = self.state
        self.state = instruction = param = None
        param_tokens = []

        while self.state not in (InterpreterStates.AWAITING_INSTRUCTION,
                                 InterpreterStates.DONE):
            try:
                token = self.program[self.pos]
            except IndexError:
                self.state = InterpreterStates.DONE
                continue

            if self.state == InterpreterStates.INSIDE_PARAMETER:
                if token in DELIMIT_PARAM:
                    param = ''.join(param_tokens)

                    if previous_state == InterpreterStates.GOT_INSTRUCTION:
                        assert instruction in NEED_PARAM + OPTIONAL_PARAM
                        self.instructions[instruction](param, self.pos)
                    self.state = InterpreterStates.AWAITING_INSTRUCTION
                else:
                    param_tokens.append(token)
            elif token in DELIMIT_PARAM:
                previous_state = self.state
                self.state = InterpreterStates.INSIDE_PARAMETER
            elif token in INSTRUCTIONS:
                instruction = token
                if ((token in NEED_PARAM or token in OPTIONAL_PARAM) and
                    self.program[self.pos + 1] in DELIMIT_PARAM):
                    self.state = InterpreterStates.GOT_INSTRUCTION
                elif (token in NO_PARAM or
                      (token in OPTIONAL_PARAM and
                       self.program[self.pos + 1] not in DELIMIT_PARAM)):
                    self.instructions[instruction]()
            else:
                # Comment, or invalid instruction (parameter required but not
                # supplied).
                pass

            self.pos += 1

    def move(self, value, pos):
        """Load a value into register X."""
        self.x.value = int(value, base=16)

    def swap(self):
        """Swap values of registers X and Y."""
        self.x, self.y = self.y, self.x

    def label(self, label, pos):
        """Store a new label."""
        self.labels[label] = pos

    def input_number(self):
        """Read a line into register X as a base-16 integer."""
        hex_input = []
        while stdin.buffer.peek()[:1] in b'0123456789ABCDEFabcdef':
            hex_input.append(stdin.buffer.read(1))
        self.x.value = int(b''.join(hex_input).decode('ASCII'), base=16)

    def input_ascii(self):
        """Read a character into register X as an ASCII character."""
        self.x.value = ord(stdin.read(1))

    def print_number(self):
        """Print register Z as a base-16 integer."""
        print(format(self.z.value, 'x'), end='')

    def print_ascii(self):
        """Print register Z as an ASCII character."""
        print(chr(self.z.value), end='')

    def roll_left(self):
        """Roll registers to the left: Z to Y to X to Z."""
        self.x, self.y, self.z = self.y, self.z, self.x

    def roll_right(self):
        """Rolle registers to the right: X to Y to Z to X."""
        self.x, self.y, self.z = self.z, self.x, self.y

    def _jump(self, label):
        """Jump to a label unconditionally."""
        try:
            self.pos = self.labels[label]
        except KeyError:
            # Is this a nonexistent label (in which case the effect is to exit
            # the program), or is it just a jump ahead?
            label_decl = '}:' + label + ':'
            ahead_pos = self.program.find(label_decl, self.pos)
            if ahead_pos == -1:
                self.state = InterpreterStates.DONE
            else:
                # Point at the start of the label declaration, so that it will
                # be read as the next instruction and the label recorded.
                self.pos = ahead_pos

    def jump_if_not_zero(self, label, pos):
        """Jump to a label if Z is not zero."""
        if self.z.value != 0:
            self._jump(label)

    def jump_if_zero(self, label, pos):
        """Jump to a label if register Z is zero."""
        if self.z.value == 0:
            self._jump(label)

    def clear(self):
        """Clear the queue."""
        self.queue = []

    def enqueue(self):
        """Enqueue the value in register Z."""
        self.queue.append(self.z.value)

    def dequeue(self):
        """Dequeue a value into register X."""
        self.x.value = self.queue.pop(0)

    def roll_queue_left(self, distance=1, pos=None):
        """Roll the queue left a given number of places."""
        if type(distance) is str:
            distance =  int(distance, base=16)
        self.queue = self.queue[distance:] + self.queue[:distance]

    def roll_queue_right(self, distance=1, pos=None):
        """Roll the queue right a given number of places."""
        if type(distance) is str:
            distance =  int(distance, base=16)
        self.queue = self.queue[-distance:] + self.queue[:-distance]

    def add(self):
        """Add registers X and Y, storing the result in Z."""
        self.z.value = self.x.value + self.y.value

    def subtract(self):
        """Subtract register Y from X, storing the result in Z."""
        self.z.value = self.x.value - self.y.value

    def multiply(self):
        """Multiply registers X and Y, storing the result in Z."""
        self.z.value = self.x.value * self.y.value

    def divide(self):
        """Divide register X by Y, storing the quotient in Z.

        The remainder is also stored, in register Y.

        """
        self.z.value, self.y.value = divmod(self.x.value, self.y.value)


if __name__ == '__main__':
    # with open(argv[1]) as program:
    #     Interpreter0815(program.read()).run()
    Interpreter0815("8;/;+(.?:;#;(+8:9?,*8/>++89<85?>:-68").run()
