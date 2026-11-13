"""Seven explicit framework 1.6 bindings used by the supplied symdemo CAP.

The identities/signatures were checked against symdemo.jca. This is a bounded
profile, not automatic compatibility with every Java Card API or version.
Existing lifecycle/APDU implementations are reused without enabling DES models.
"""
from pysoot_adapter import ClassMetadata
from .javacard_api import APIModel, FW, Name1API


class SymDemoAPI(Name1API):
    name = 'symdemo-fw16-subset-v1'
    classes = (
        ClassMetadata(FW + 'Applet', 'java.lang.Object', attrs=('PUBLIC', 'ABSTRACT')),
        ClassMetadata(FW + 'APDU', 'java.lang.Object', attrs=('PUBLIC', 'FINAL')),
    )

    def __init__(self):
        # Deliberately do not call Name1API.__init__: no crypto dependency/models.
        bindings = (
            (3, 6, 0, 'Applet', '<init>', (), 'void', False, 'applet_init'),
            (3, 3, 2, 'Applet', 'register', ('byte[]', 'short', 'byte'), 'void', False, 'register'),
            (3, 3, 3, 'Applet', 'selectingApplet', (), 'boolean', False, 'selecting'),
            (10, 3, 1, 'APDU', 'getBuffer', (), 'byte[]', False, 'get_buffer'),
            (10, 3, 6, 'APDU', 'setIncomingAndReceive', (), 'short', False, 'receive'),
            (10, 3, 8, 'APDU', 'setOutgoingAndSend', ('short', 'short'), 'void', False, 'send'),
            (7, 6, 1, 'ISOException', 'throwIt', ('short',), 'void', True, 'throw_iso'),
        )
        self.models = {}
        for cls, tag, token, owner, name, params, returns, static, handler in bindings:
            key = f'a0000000620101@1.6:c{cls}:t{tag}:m{token}'
            self.models[key] = APIModel(key, FW + owner, name, params, returns, static,
                                       handler, None if static or name == '<init>' else token)
