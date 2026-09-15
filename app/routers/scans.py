"""Endpoints for safe URL and file triage."""
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, HttpUrl

from ..services.scanning import MAX_FILE_BYTES, scan_file, scan_url

router = APIRouter(prefix="/scans", tags=["Threat triage"])


class UrlScanRequest(BaseModel):
    url: HttpUrl


@router.post("/url")
def triage_url(request: UrlScanRequest):
    try:
        return scan_url(str(request.url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/file")
async def triage_file(file: UploadFile = File(...)):
    content = await file.read(MAX_FILE_BYTES + 1)
    try:
        return scan_file(file.filename or "", content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()
