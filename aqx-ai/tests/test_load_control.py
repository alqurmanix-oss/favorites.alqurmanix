import asyncio

from starlette.requests import Request
from starlette.responses import Response

from app import main


def _request(path: str = "/v1/analyze") -> Request:
    return Request({
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    })


def test_inference_admission_is_bounded_and_releases_slots():
    async def run_requests():
        async def call_next(_request):
            await asyncio.sleep(0.03)
            return Response(status_code=200)

        responses = await asyncio.gather(*[
            main.bound_inference_load(_request(), call_next)
            for _ in range(main._INFERENCE_CAPACITY + 1)
        ])
        return [response.status_code for response in responses]

    statuses = asyncio.run(run_requests())
    assert statuses.count(429) == 1
    assert statuses.count(200) == main._INFERENCE_CAPACITY
    assert main._admitted_requests == 0


def test_non_inference_routes_bypass_admission_limit():
    async def run_request():
        async def call_next(_request):
            return Response(status_code=204)

        response = await main.bound_inference_load(_request("/health"), call_next)
        return response.status_code

    assert asyncio.run(run_request()) == 204
