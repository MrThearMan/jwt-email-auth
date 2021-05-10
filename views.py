from typing import Dict, Any, Union

from django.http.request import QueryDict

from rest_framework import status
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework.authentication import get_authorization_header


__all__ = [
    "BaseAPIView",
]


class BaseAPIView(APIView):

    serializer_classes = {}
    """Key: method name (uppercase), value: serializer class."""
    permission_classes = []
    authentication_classes = []
    status_ok = status.HTTP_200_OK

    def get_serializer(self, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        kwargs.setdefault("context", self.get_serializer_context())
        return serializer_class(*args, **kwargs)

    def get_serializer_class(self):
        return self.serializer_classes[self.request.method]

    def get_serializer_context(self) -> Dict[str, Any]:
        return {"request": self.request, "view": self}

    def run_serializer(self, request: Request, data: Dict[str, Any], *args, **kwargs) -> Response:
        if self.permission_classes or self.authentication_classes:
            data.setdefault("token", get_authorization_header(request).split()[1].decode())

        data.update(**kwargs)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if request.method == "GET":
            data = self.handle_get(request, data, *args, **kwargs)
        elif request.method == "POST":
            data = self.handle_post(request, data, *args, **kwargs)
        elif request.method == "PUT":
            data = self.handle_put(request, data, *args, **kwargs)
        elif request.method == "PATCH":
            data = self.handle_patch(request, data, *args, **kwargs)
        elif request.method == "DELETE":
            data = self.handle_delete(request, data, *args, **kwargs)

        return Response(data=data, status=self.status_ok)
