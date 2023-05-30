import json
from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer


class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        async_to_sync(self.channel_layer.group_add)("chats", self.channel_name)

    def disconnect(self, close_code):
        async_to_sync(self.channel_layer.group_discard)("chats", self.channel_name)

    def receive(self, text_data=None, bytes_data=None):
        data = json.loads(text_data)
        message = data['message']
        async_to_sync(self.channel_layer.group_send)(
            'chats', {
                "type": 'send_message_to_frontend',
                "message": message
            }
        )

    def send_message_to_frontend(self, event):
        message = event['message']
        print(message)
        self.send(text_data=json.dumps({
            'message': message
        }))
