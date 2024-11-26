import unittest
import json
from app import app
from auth import generate_token

class EdgeCaseTestCase(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.token = generate_token(user_id=1)

    def test_empty_message_encryption(self):
        response = self.app.post('/encrypt-message',
                                 headers={'x-access-token': self.token},
                                 data=json.dumps({'message': ''}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)

    def test_large_message_encryption(self):
        large_message = 'A' * 10000  # 10,000 characters
        response = self.app.post('/encrypt-message',
                                 headers={'x-access-token': self.token},
                                 data=json.dumps({'message': large_message}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('encrypted_message', data)

    def test_invalid_json_format(self):
        response = self.app.post('/encrypt-message',
                                 headers={'x-access-token': self.token},
                                 data='not a json',
                                 content_type='application/json')
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
