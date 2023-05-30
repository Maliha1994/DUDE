import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import feast_app.routing

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "feast.settings")

application = ProtocolTypeRouter({
  "http": get_asgi_application(),
  "websocket": AuthMiddlewareStack(
        URLRouter(
            feast_app.routing.websocket_urlpatterns
        )
    ),
})