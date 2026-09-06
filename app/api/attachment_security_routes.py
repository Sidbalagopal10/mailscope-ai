from __future__ import annotations

from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
)

from app.attachment_security.inspector import (
    AttachmentInspectionError,
    MAX_FILE_SIZE,
    inspect_attachment_bytes,
)


router = APIRouter(
    prefix="/attachment-security",
    tags=["Attachment Security"],
)


@router.post("/inspect")
async def inspect_attachment(
    file: UploadFile = File(...),
):
    try:
        data = await file.read(
            MAX_FILE_SIZE + 1
        )

        if len(
            data
        ) > MAX_FILE_SIZE:
            raise AttachmentInspectionError(
                "Attachment exceeds the safe inspection limit."
            )

        return inspect_attachment_bytes(
            filename=(
                file.filename
                or "attachment.bin"
            ),
            data=data,
            declared_mime_type=(
                file.content_type
            ),
        )

    except AttachmentInspectionError as error:
        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(
                error
            ),
        ) from error

    finally:
        await file.close()
