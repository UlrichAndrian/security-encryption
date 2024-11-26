import unittest
import json
from app import app
from auth import generate_token

class APITestCase(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.token = generate_token(user_id=1)

    def test_generate_password(self):
        response = self.app.get('/generate-password', headers={'x-access-token': self.token})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('password', data)

    def test_encrypt_message(self):
        message = "Hello, World!"
        response = self.app.post('/encrypt-message',
                                 headers={'x-access-token': self.token},
                                 data=json.dumps({'message': message}),
                                 content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('encrypted_message', data)

    def test_decrypt_message(self):
        # First, encrypt a message to get an encrypted_message
        message = "Hello, World!"
        encrypt_response = self.app.post('/encrypt-message',
                                         headers={'x-access-token': self.token},
                                         data=json.dumps({'message': message}),
                                         content_type='application/json')
        encrypted_message = json.loads(encrypt_response.data)['encrypted_message']

        # Now, decrypt the message
        decrypt_response = self.app.post('/decrypt-message',
                                         headers={'x-access-token': self.token},
                                         data=json.dumps({'encrypted_message': encrypted_message}),
                                         content_type='application/json')
        self.assertEqual(decrypt_response.status_code, 200)
        data = json.loads(decrypt_response.data)
        self.assertEqual(data['decrypted_message'], message)

    def test_invalid_token(self):
        response = self.app.get('/generate-password', headers={'x-access-token': 'invalid_token'})
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
