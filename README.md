This app has an issue. The POST endpoints can create valid JWTs—I checked them on https://jwt.io/ and 
confirmed that the payload had the appropriate structure, an unexpired exp, and a valid signature. 
However, when using these JWTs with the GET endpoints that simulate accessing user and admin resources, 
I receive a 401 error.

What’s strange is that the error message says the JSON Web Token (JWT) is malformed because it lacks the
required period (.) separators, even though the token does include the periods as expected.


Objective: Authorization Techniques – Implementing Role-Based Access Control (RBAC)
Tools: Visual Studio Code, Postman, C#, .NET 8.0.
List: RBAC Implementation Steps

    Create Roles and Permissions: Define roles (e.g., Admin, User) and assign them permissions. (Define: Role-Based Access Control)
    Apply RBAC Logic: Implement code to restrict access to specific resources based on roles.
    Test Role-Based Access: Verify that users only access what their role allows.

You can test this app by using this cURLs: 

Test admin :
        curl --location 'http://localhost:5171/login' \
        --header 'Content-Type: application/json' \
        --data '{
            "username": "admin",
            "password": "admin123"
        }'

Test user: 
      curl --location 'http://localhost:5171/login' \
      --header 'Content-Type: application/json' \
      --data '{
          "username": "user",
          "password": "user123"
      }'

Test Admin panel:

curl --location 'http://localhost:5171/secure/admin-panel' \
--header 'Authorization: Bearer YOUR_TOKEN'

Test user panel:

curl --location 'http://localhost:5171/secure/user-profile' \
--header 'Authorization: Bearer YOUR_TOKEN'

Error sample:

Token received: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiYWRtaW4iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJBZG1pbiIsImV4cCI6MTczNDk5NTE2NSwiaXNzIjoiWW91cklzc3VlciIsImF1ZCI6IllvdXJBdWRpZW5jZSJ9.zZyJG3T4B7A6ft--5jJq8clGFg2ZG2Yntn4LzMRlI9I
Authentication failed: IDX14100: JWT is not well formed, there are no dots (.).
The token needs to be in JWS or JWE Compact Serialization Format. (JWS): 'EncodedHeader.EndcodedPayload.EncodedSignature'. (JWE): 'EncodedProtectedHeader.EncodedEncryptedKey.EncodedInitializationVector.EncodedCiphertext.EncodedAuthenticationTag'.
An authentication challenge has been initiated.
