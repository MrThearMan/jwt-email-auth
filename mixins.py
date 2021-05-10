from typing import Optional, Dict, Union

from django.http.request import QueryDict

from rest_framework.response import Response
from rest_framework.request import Request


__all__ = [
    "GetMixin",
    "PostMixin",
    "PutMixin",
    "PatchMixin",
    "DeleteMixin",
]


class GetMixin:
    def get(self, request: Request, *args, **kwargs) -> Response:
        # [sic] QueryDicts are immutable, and token might need to be added.
        data = {key: value for key, value in request.query_params.items()}
        return self.run_serializer(request, data, *args, **kwargs)

    def handle_get(self, request: Request, data: Union[Dict, QueryDict], *args, **kwargs) -> Optional[Dict]:
        """Optional step where get request response data can be handled further."""
        return data


class PostMixin:
    def post(self, request: Request, *args, **kwargs) -> Response:
        return self.run_serializer(request, request.data, *args, **kwargs)

    def handle_post(self, request: Request, data: Union[Dict, QueryDict], *args, **kwargs) -> Optional[Dict]:
        """Optional step where post request response data can be handled further."""
        return data


class PutMixin:
    def put(self, request: Request, *args, **kwargs) -> Response:
        return self.run_serializer(request, request.data, *args, **kwargs)

    def handle_put(self, request: Request, data: Union[Dict, QueryDict], *args, **kwargs) -> Optional[Dict]:
        """Optional step where put request response data can be handled further."""
        return data


class PatchMixin:
    def patch(self, request: Request, *args, **kwargs) -> Response:
        return self.run_serializer(request, request.data, *args, **kwargs)

    def handle_patch(self, request: Request, data: Union[Dict, QueryDict], *args, **kwargs) -> Optional[Dict]:
        """Optional step where patch request response data can be handled further."""
        return data


class DeleteMixin:
    def delete(self, request: Request, *args, **kwargs) -> Response:
        return self.run_serializer(request, request.data, *args, **kwargs)

    def handle_delete(self, request: Request, data: Union[Dict, QueryDict], *args, **kwargs) -> Optional[Dict]:
        """Optional step where delete request response data can be handled further."""
        return data
