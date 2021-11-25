# Usage

1. Send a login code to the *authentication* endpoint (from `SendLoginCodeView` class).

|Request|Response|
|---|---|
|POST [Authentication URI] <br>Content-Type: application/json|HTTP 204 NO CONTENT
|{<br>  "email":"person@example.com"<br>}|...|


2. POST the login code and email to *login* endpoint (from `LoginView` class).

|Request|Response|
|---|---|
|POST [Login URI] <br>Content-Type: application/json|HTTP 202 ACCEPTED
|{<br>  "email":"person@example.com"<br>  "code":"123222"<br>}|{<br>  "access":"..."<br>  "refresh":"..."<br>}|


3. Refresh access token from the *refresh token* endpoint (from `RefreshTokenView` class).

|Request|Response|
|---|---|
|POST [Refresh Token URI] <br>Content-Type: application/json|HTTP 200 OK
|{<br>  "token":"..."<br>}|{<br>  "access":"..."<br>}|


## Authentication and Permission classes

Add the `JWTAuthentication` or `HasValidJWT`
to Rest framework's settings or or to the classe's authentication or permission classes

```python
from rest_framework.views import APIView
from jwt_email_auth.authentication import JWTAuthentication
from jwt_email_auth.permissions import HasValidJWT


class SomeView(APIView):

   authentication_classes = [JWTAuthentication]
   permission_classes = [HasValidJWT]

   ...
```

## Base Access Serializer

If you need to use claims from the token in you code, you can use the `BaseAccessSerializer`.

```python
from rest_framework import serializers
from rest_framework.views import APIView
from jwt_email_auth.serializers import BaseAccessSerializer


class SomeSerializer(BaseAccessSerializer):

   take_form_token = ["example", "values"]

   some = serializers.CharField()
   data = serializers.CharField()

   ...


class SomeView(APIView):

    def post(self, request, *args, **kwargs):

        data = {"some": ..., "data": ...}

        # Request is needed in serializer context to get the access token
        serializer = SomeSerializer(data=data, context={"request", request})
        data = serializer.initial_data

        # ...or this:
        # serializer.is_valid(raise_exception=True)
        # data = serializer.validated_data

        # ...or this:
        # data = serializer.data

        print(data)  # {"some": ..., "data": ..., "example": ..., "values": ...}
        ...
```

