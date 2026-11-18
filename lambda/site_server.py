"""Serve files from the private website bucket through API Gateway."""
import base64
import mimetypes
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
BUCKET = os.environ["WEBSITE_BUCKET"]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'",
}

TEXT_TYPES = ("text/", "application/json", "application/javascript", "image/svg+xml")


def response(status, body, content_type, binary=False):
    headers = {"Content-Type": content_type, "Cache-Control": "public, max-age=300"}
    headers.update(SECURITY_HEADERS)
    return {
        "statusCode": status,
        "headers": headers,
        "body": body,
        "isBase64Encoded": binary,
    }


def not_found():
    try:
        page = s3.get_object(Bucket=BUCKET, Key="error.html")["Body"].read().decode("utf-8", "replace")
    except ClientError:
        page = "<h1>404</h1><p>That page does not exist.</p>"
    return response(404, page, "text/html")


def handler(event, context):
    if event.get("httpMethod") != "GET":
        return response(405, "Method not allowed", "text/plain")

    params = event.get("pathParameters") or {}
    key = (params.get("proxy") or "").lstrip("/")
    if not key or key.endswith("/"):
        key += "index.html"
    if ".." in key.split("/"):
        return response(400, "Bad request", "text/plain")

    try:
        obj = s3.get_object(Bucket=BUCKET, Key=key)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            return not_found()
        # AccessDenied here means the bucket is isolated or misconfigured
        return response(503, "Service temporarily unavailable", "text/plain")

    data = obj["Body"].read()
    content_type = obj.get("ContentType") or mimetypes.guess_type(key)[0] or "application/octet-stream"
    if content_type.startswith(TEXT_TYPES):
        return response(200, data.decode("utf-8", "replace"), content_type)
    return response(200, base64.b64encode(data).decode("ascii"), content_type, binary=True)
