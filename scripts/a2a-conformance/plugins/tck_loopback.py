"""pytest plugin the harness loads into both A2A TCK versions.

Each suite starts a webhook receiver when one of its push notification tests
runs, even a test that then skips itself, and the receiver listens on every
interface. The harness keeps everything it starts on loopback, so this plugin
narrows the receiver to 127.0.0.1.
"""

from tck.webhook.server import WebhookReceiver

LOOPBACK = '127.0.0.1'

_init = WebhookReceiver.__init__


def init_on_loopback(self: WebhookReceiver, *args: object, **kwargs: object) -> None:
    _init(self, *args, **kwargs)
    self.host = LOOPBACK


WebhookReceiver.__init__ = init_on_loopback
