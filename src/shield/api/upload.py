"""Read one file field of a multipart upload into memory, with a hard size cap, without ever touching the disk.

Why not FastAPI's UploadFile / request.form(): Starlette keeps a file part in a SpooledTemporaryFile(max_size=1 MB) and writes anything
bigger to a temp file on disk. An ordinary phone screenshot is 1-3 MB, so that would store the image (D19: the image is never stored).
Here the python-multipart parser is fed the request stream directly, the one wanted part is collected into a bytearray, and the cap is
enforced as the bytes arrive (an oversize body is refused before it is read in full).
"""
from python_multipart.multipart import MultipartParser, parse_options_header

OVERHEAD = 64 * 1024   # room in the body for the boundary lines and the part headers around a file of max_bytes


class UploadTooLarge(Exception):
    pass

class BadUpload(Exception):
    """Not multipart/form-data, malformed, or the field is missing / empty."""


async def read_part(request, field, max_bytes):
    """The bytes of the multipart part named `field`. Raises UploadTooLarge (body or part over the cap) or BadUpload."""
    mime, params = parse_options_header(request.headers.get("content-type", ""))
    boundary = params.get(b"boundary")
    if mime != b"multipart/form-data" or not boundary:
        raise BadUpload
    limit = max_bytes + OVERHEAD
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise UploadTooLarge   # refused before any of the body is read

    st = {"hf": b"", "hv": b"", "headers": {}, "active": False, "done": False}
    data = bytearray()

    def part_begin():
        st.update(hf=b"", hv=b"", headers={}, active=False)
    def header_field(b, s, e):
        st["hf"] += b[s:e]
    def header_value(b, s, e):
        st["hv"] += b[s:e]
    def header_end():
        st["headers"][st["hf"].lower()] = st["hv"]
        st["hf"] = st["hv"] = b""
    def headers_finished():
        _, p = parse_options_header(st["headers"].get(b"content-disposition", b""))
        st["active"] = p.get(b"name") == field.encode() and not st["done"]
    def part_data(b, s, e):
        if st["active"]:
            if len(data) + (e - s) > max_bytes:
                raise UploadTooLarge
            data.extend(b[s:e])
    def part_end():
        if st["active"]:
            st["done"], st["active"] = True, False

    parser = MultipartParser(boundary, {"on_part_begin": part_begin, "on_header_field": header_field, "on_header_value": header_value,
                                        "on_header_end": header_end, "on_headers_finished": headers_finished, "on_part_data": part_data,
                                        "on_part_end": part_end})
    seen = 0
    try:
        async for chunk in request.stream():
            seen += len(chunk)
            if seen > limit:
                raise UploadTooLarge
            parser.write(chunk)
        parser.finalize()
    except UploadTooLarge:
        raise
    except Exception:
        raise BadUpload from None   # a malformed body: nothing from it goes into the error
    if not data:
        raise BadUpload
    return bytes(data)
