```toml
name = 'Add'
method = 'POST'
url = 'http://localhost:8081/api/users/create'
sortWeight = 1000000
id = '603ba9b2-0856-43e0-9872-c53b48de88b3'

[body]
type = 'JSON'
raw = '''
{
  "username": "john_doe",
  "email": "parmeshb119@gmail.com",
  "firstName": "John",
  "lastName": "Doe",
  "enabled": true,
  "emailVerified":true,
  "requiredActions":[
    "UPDATE_PASSWORD",
  ],
  "clientRoles": {
    "config":["ADMIN"]
  },
  "credentials": [
    {
      "type": "password",
      "value": "securePassword123",
      "temporary": true
    }
  ]
}'''
```
