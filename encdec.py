import base64
import random
from functools import wraps


UNKNOWN = object()
DEFAULT_TEST = lambda string, salt, password: UNKNOWN
code_a = ord('a')
code_z = ord('z')
code_A = ord('A')
code_F = ord('F')
code_Z = ord('Z')
code_0 = ord('0')
code_2 = ord('2')
code_7 = ord('7')
code_9 = ord('9')
code_eq = ord('=')

def no_salt_or_pass(function):
    @wraps(function)
    def wrapper(string, salt, password):
        return function(string)
    return wrapper

@no_salt_or_pass
def rot13encode(string):
	return string.encode('rot13')

@no_salt_or_pass
def rot13decode(string):
	return string.decode('rot13')

@no_salt_or_pass
def test_b16(string):
    for char in string:
        try:
            code = ord(char)
        except:
            return False
        else:
            ok = code_A <= code <= code_F or \
                 code_0 <= code <= code_9
            if not ok:
                return False
    return UNKNOWN

@no_salt_or_pass
def test_b32(string):
    for char in string:
        try:
            code = ord(char)
        except:
            return False
        else:
            ok = code_A <= code <= code_Z or \
                 code_2 <= code <= code_7 or \
                 code_eq == code
            if not ok:
                return False
    return UNKNOWN

@no_salt_or_pass
def test_b64(string):
    for index, char in enumerate(string):
        try:
            code = ord(char)
        except:
            return False
        else:
            ok = code_a <= code <= code_z or \
                 code_A <= code <= code_Z or \
                 code_0 <= code <= code_9 or \
                 char == '+' or \
                 char == '/' or \
                 code_eq == code
            if not ok:
                return False
    return UNKNOWN

class Encoder(object):

    def __init__(self, name, enc, dec, test):
        self.name = name
        self.encoder = enc
        self.decoder = dec
        self.test = test

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def encode(self, string, salt, password):
        return self.encoder(string, salt, password)

    def decode(self, string, salt, password):
        return self.decoder(string, salt, password)

    def is_variety(self, string, salt, password):
        try:
            result = self.test(string, salt, password)
            if result is UNKNOWN:
                self.decode(string, salt, password)
            return result
        except:
            return False

class EncoderStackItem(object):

    def __init__(self, encoder, salt, password):
        self.encoder = encoder
        self.salt = salt
        self.password = password

    def __str__(self):
        if self.password is not None:
            if self.salt is not None:
                return '%s:%s:%s' % (self.encoder.name, self.salt, self.password)
            else:
                return '%s:%s' % (self.encoder.name, self.password)
        return self.encoder.name

    def __repr__(self):
        return self.__str__()

class Cracker(object):

    B64Encoder = Encoder('Base64', no_salt_or_pass(base64.b64encode), no_salt_or_pass(base64.b64decode), test_b64)
    B32Encoder = Encoder('Base32', no_salt_or_pass(base64.b32encode), no_salt_or_pass(base64.b32decode), test_b32)
    B16Encoder = Encoder('Base16', no_salt_or_pass(base64.b16encode), no_salt_or_pass(base64.b16decode), test_b16)
    Rot13Encoder = Encoder('Rot-13', rot13encode, rot13decode, DEFAULT_TEST)

    ENCODERS = [B64Encoder, B32Encoder, B16Encoder, Rot13Encoder]

    def generate_random_selections(self, seq, count):
        last = len(seq) - 1
        return (seq[random.randint(0, last)] for _ in xrange(count))

    def loop(self, seq):
        if isinstance(seq, (list, tuple)):
            if len(seq):
                while True:
                    for obj in seq:
                        yield obj
            else:
                while True:
                    yield None
        else:
            while True:
                yield seq

    def encode(self, string, level, salts=(), passwords=()):
        encoders = self.generate_random_selections(Cracker.ENCODERS, level)
        salts = self.loop(salts)
        passwords = self.loop(passwords)
        stack = []
        for index, encoder in enumerate(encoders):
            salt = salts.next()
            password = passwords.next()
            string = encoder.encode(string, salt, password)
            stack.append(encoder)
        return stack, string

    def decode(self, string, max_levels=10, min_levels=0, salts=(), passwords=()):
        salts = self.loop(salts)
        passwords = self.loop(passwords)
        self._continue(string, salts, passwords, min_levels, max_levels, [])

    def _continue(self, string, salts, passwords, min_index, max_index, stack):
        index = len(stack)
        salt = salts.next()
        password = passwords.next()
        for encoder in Cracker.ENCODERS:
            test_result = encoder.is_variety(string, salt, password)
            stack_item = EncoderStackItem(encoder, salt, password)
            stack_copy = stack[:] + [stack_item]
            if test_result in (UNKNOWN, True):
                self._check_possibility(string, salt, salts, password, passwords, min_index, max_index, stack_copy)
        
    def _print_stack(self, decoded, salt, password, stack):
        print '|'.join((str(stack_item) for stack_item in stack)), decoded

    def _check_possibility(self, string, salt, salts, password, passwords, min_index, max_index, stack):
        index = len(stack)
        decoded = stack[-1].encoder.decode(string, salt, password)
        if index >= min_index:
            self._print_stack(decoded, salt, password, stack)
        if index < max_index:
            self._continue(decoded, salts, passwords, min_index, max_index, stack)

