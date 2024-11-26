# API Documentation

## Overview
This API provides functionalities for secure password generation and message encryption/decryption. It uses JWT for authentication to ensure that only authorized users can access the endpoints.

## Authentication
To access the API, you must include a valid JWT token in the `x-access-token` header of your requests. Tokens can be generated using the `generate_token` function in the `auth.py` module.

## Endpoints

### Generate Password
- **URL**: `/generate-password`
- **Method**: `GET`
- **Headers**: `x-access-token: <your_jwt_token>`
- **Response**: 
  - **200 OK**: `{ "password": "<generated_password>" }`

### Encrypt Message
- **URL**: `/encrypt-message`
- **Method**: `POST`
- **Headers**: `x-access-token: <your_jwt_token>`
- **Body**: `{ "message": "<your_message>" }`
- **Response**: 
  - **200 OK**: `{ "encrypted_message": "<encrypted_message>" }`

### Decrypt Message
- **URL**: `/decrypt-message`
- **Method**: `POST`
- **Headers**: `x-access-token: <your_jwt_token>`
- **Body**: `{ "encrypted_message": "<your_encrypted_message>" }`
- **Response**: 
  - **200 OK**: `{ "decrypted_message": "<decrypted_message>" }`

## Error Handling
Common errors include missing or invalid tokens and malformed requests. Ensure your requests include the correct headers and body format.

- **401 Unauthorized**: Occurs when the token is missing or invalid.
- **400 Bad Request**: Occurs when the request body is malformed or missing required fields.

## Examples
### Request Example for Generating a Password
```
GET /generate-password
Headers:
  x-access-token: <your_jwt_token>
```

### Request Example for Encrypting a Message
```
POST /encrypt-message
Headers:
  x-access-token: <your_jwt_token>
Body:
  { "message": "Hello, World!" }
```

### Request Example for Decrypting a Message
```
POST /decrypt-message
Headers:
  x-access-token: <your_jwt_token>
Body:
  { "encrypted_message": "<your_encrypted_message>" }
```
