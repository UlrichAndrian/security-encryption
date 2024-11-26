import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


def test_generate_password(client):
    response = client.get('/generate-password')
    assert response.status_code == 200
    assert 'password' in response.get_json()


def test_encrypt_message(client):
    response = client.post('/encrypt-message', json={'message': 'Hello'})
    assert response.status_code == 401  # Assuming no token is provided
