
import os
import uuid
from pathlib import Path
from database import create_tables

from fastapi import (
    FastAPI, HTTPException, Depends, UploadFile, File, Form
)
from pydantic import BaseModel
from datetime import datetime, timezone
from database import get_connection
from auth import verify_password, create_access_token, get_current_user
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(title="TrustVault API")
create_tables()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "null",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/")
def home():
    return FileResponse(Path(__file__).resolve().parent / "index.html")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/login")
def login(data: LoginRequest):
    connection = get_connection()

    try:
        user = connection.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()
    finally:
        connection.close()

    if user is None or not verify_password(
        data.password, user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token(user["id"], user["role"])

    return {"access_token": token, "token_type": "bearer"}


@app.post("/documents/upload")
def upload_document(
    category: str = Form(...),
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] not in ("admin", "owner"):
        raise HTTPException(
            status_code=403,
            detail="Only admins and document owners can upload"
        )

    original_name = Path(file.filename or "").name.strip()
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="File type not allowed"
        )

    if file.content_type != ALLOWED_TYPES[extension]:
        raise HTTPException(
            status_code=400,
            detail="File content type does not match its extension"
        )

    category = category.strip()
    if not category or len(category) > 50:
        raise HTTPException(
            status_code=400,
            detail="Category must contain 1 to 50 characters"
        )

    stored_name = f"{uuid.uuid4().hex}{extension}"
    file_path = STORAGE_DIR / stored_name
    total_size = 0

    try:
        with file_path.open("xb") as destination:
            while True:
                chunk = file.file.read(64 * 1024)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds 10 MB limit"
                    )

                destination.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty files are not allowed"
            )

        connection = get_connection()
        try:
            cursor = connection.execute(
                """INSERT INTO documents
                   (filename, stored_filename, category, owner_id)
                   VALUES (?, ?, ?, ?)""",
                (
                    original_name,
                    stored_name,
                    category,
                    current_user["id"]
                )
            )
            document_id = cursor.lastrowid

            connection.execute(
                """INSERT INTO audit_logs
                   (actor_user_id, document_id, action, details)
                   VALUES (?, ?, ?, ?)""",
                (
                    current_user["id"],
                    document_id,
                    "UPLOAD",
                    f"Uploaded {original_name}"
                )
            )

            connection.commit()
        finally:
            connection.close()

        return {
            "message": "Document uploaded successfully",
            "document_id": document_id,
            "filename": original_name,
            "size_bytes": total_size
        }

    except Exception:
        file_path.unlink(missing_ok=True)
        raise


@app.get("/documents")
def list_documents(
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()
    try:
        if current_user["role"] == "admin":
            documents = connection.execute(
                """SELECT id, filename, category, owner_id, uploaded_at
                   FROM documents ORDER BY id DESC"""
            ).fetchall()
        else:
            documents = connection.execute(
                """SELECT DISTINCT d.id, d.filename, d.category,
                          d.owner_id, d.uploaded_at
                   FROM documents d
                   LEFT JOIN permissions p
                     ON p.document_id = d.id AND p.user_id = ?
                   WHERE d.owner_id = ?
                      OR (p.user_id IS NOT NULL AND p.can_read = 1)
                   ORDER BY d.id DESC""",
                (current_user["id"], current_user["id"])
            ).fetchall()

        return {"documents": [dict(row) for row in documents]}
    finally:
        connection.close()

class PermissionRequest(BaseModel):
    username: str
    can_read: bool = False
    can_edit: bool = False
    expires_at: datetime | None = None


@app.post("/documents/{document_id}/permissions")
def grant_permission(
    document_id: int,
    data: PermissionRequest,
    current_user: dict = Depends(get_current_user)
):
    if not data.can_read and not data.can_edit:
        raise HTTPException(
            status_code=400,
            detail="Grant read or edit permission"
        )

    connection = get_connection()
    try:
        document = connection.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        if current_user["role"] != "admin" and document["owner_id"] != current_user["id"]:
            raise HTTPException(
                status_code=403,
                detail="Only the owner or admin can manage permissions"
            )

        target = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (data.username,)
        ).fetchone()

        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        if target["id"] == document["owner_id"]:
            raise HTTPException(status_code=400, detail="Owner already has access")

        expires_at = None

        if data.expires_at is not None:
            expiry = data.expires_at

            if expiry.tzinfo is None:
                raise HTTPException(
                    status_code=400,
                    detail="Expiry must include a timezone"
                )

            if expiry <= datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=400,
                    detail="Expiry must be in the future"
                )

            expires_at = expiry.astimezone(timezone.utc).isoformat()

        connection.execute(
            """INSERT INTO permissions
               (document_id, user_id, can_read, can_edit, expires_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(document_id, user_id)
               DO UPDATE SET
                   can_read = excluded.can_read,
                   can_edit = excluded.can_edit,
                   expires_at = excluded.expires_at""",
            (
                document_id,
                target["id"],
                int(data.can_read or data.can_edit),
                int(data.can_edit),
                expires_at
            )
        )  

        connection.execute(
            """INSERT INTO audit_logs
               (actor_user_id, document_id, action, details)
               VALUES (?, ?, ?, ?)""",
            (
                current_user["id"],
                document_id,
                "PERMISSION_GRANTED",
                f"Permissions updated for user {data.username}"
            )
        )
        connection.commit()

        return {"message": "Permissions updated successfully"}
    finally:
        connection.close()


@app.delete("/documents/{document_id}/permissions/{username}")
def revoke_permission(
    document_id: int,
    username: str,
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()
    try:
        document = connection.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        if current_user["role"] != "admin" and document["owner_id"] != current_user["id"]:
            raise HTTPException(
                status_code=403,
                detail="Only the owner or admin can manage permissions"
            )

        target = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if target is None:
            raise HTTPException(status_code=404, detail="User not found")

        cursor = connection.execute(
            "DELETE FROM permissions WHERE document_id = ? AND user_id = ?",
            (document_id, target["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Permission not found")

        connection.execute(
            """INSERT INTO audit_logs
               (actor_user_id, document_id, action, details)
               VALUES (?, ?, ?, ?)""",
            (
                current_user["id"],
                document_id,
                "PERMISSION_REVOKED",
                f"Permissions revoked for user {username}"
            )
        )
        connection.commit()

        return {"message": "Permission revoked successfully"}
    finally:
        connection.close()


from fastapi.responses import FileResponse


@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()

    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        allowed = current_user["role"] == "admin"
        allowed = allowed or document["owner_id"] == current_user["id"]

        if not allowed:
            permission = connection.execute(
                 """SELECT can_read, expires_at FROM permissions
                   WHERE document_id = ? AND user_id = ?""",
                (document_id, current_user["id"])
            ).fetchone()

            allowed = (
                permission is not None
                and permission["can_read"] == 1
                and (
                    permission["expires_at"] is None
                    or datetime.fromisoformat(
                        permission["expires_at"]
                    ) > datetime.now(timezone.utc)
                )
            )

            if not allowed:
               connection.execute(
                """INSERT INTO audit_logs
                   (actor_user_id, document_id, action, details)
                   VALUES (?, ?, ?, ?)""",
                (
                    current_user["id"],
                    document_id,
                    "DOWNLOAD_DENIED",
                    "User attempted unauthorized download"
                )
            )

            attempts = connection.execute(
                """SELECT COUNT(*) FROM audit_logs
                   WHERE actor_user_id = ?
                     AND action IN ('DOWNLOAD_DENIED', 'EDIT_DENIED')
                     AND created_at >= datetime('now', '-5 minutes')""",
                (current_user["id"],)
            ).fetchone()[0]

            if attempts >= 3:
                recent_alert = connection.execute(
                    """SELECT id FROM alerts
                       WHERE actor_user_id = ?
                         AND alert_type = ?
                         AND resolved = 0
                         AND created_at >= datetime('now', '-5 minutes')
                       LIMIT 1""",
                    (current_user["id"], "REPEATED_UNAUTHORIZED_ACCESS")
                ).fetchone()

                if recent_alert is None:
                    connection.execute(
                        """INSERT INTO alerts
                           (actor_user_id, document_id, alert_type, details)
                           VALUES (?, ?, ?, ?)""",
                        (
                            current_user["id"],
                            document_id,
                            "REPEATED_UNAUTHORIZED_ACCESS",
                            f"{attempts} unauthorized attempts within 5 minutes"
                        )
                    )

            connection.commit()

            raise HTTPException(
                status_code=403,
                detail="You do not have permission to download this document"
            )


        file_path = (STORAGE_DIR / document["stored_filename"]).resolve()

        if file_path.parent != STORAGE_DIR.resolve() or not file_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Stored document not found"
            )

        connection.execute(
            """INSERT INTO audit_logs
               (actor_user_id, document_id, action, details)
               VALUES (?, ?, ?, ?)""",
            (
                current_user["id"],
                document_id,
                "DOWNLOAD",
                "Document downloaded"
            )
        )
        connection.commit()

        return FileResponse(
            path=str(file_path),
            filename=document["filename"]
        )
    finally:
        connection.close()

class DocumentUpdate(BaseModel):
    filename: str | None = None
    category: str | None = None


@app.patch("/documents/{document_id}")
def edit_document(
    document_id: int,
    data: DocumentUpdate,
    current_user: dict = Depends(get_current_user)
):
    if data.filename is None and data.category is None:
        raise HTTPException(
            status_code=400,
            detail="Provide a filename or category to update"
        )

    if data.filename is not None:
        if (
            not data.filename.strip()
            or len(data.filename) > 255
            or Path(data.filename).name != data.filename
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid filename"
            )

    if data.category is not None:
        if not data.category.strip() or len(data.category) > 50:
            raise HTTPException(
                status_code=400,
                detail="Category must contain 1 to 50 characters"
            )

    connection = get_connection()
    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")

        allowed = (
            current_user["role"] == "admin"
            or document["owner_id"] == current_user["id"]
        )

        if not allowed:
            permission = connection.execute(
                 """SELECT can_edit, expires_at FROM permissions
                   WHERE document_id = ? AND user_id = ?""",   
                (document_id, current_user["id"])
            ).fetchone()

            allowed = (
                permission is not None
                and permission["can_edit"] == 1
                and (
                    permission["expires_at"] is None
                    or datetime.fromisoformat(
                        permission["expires_at"]
                    ) > datetime.now(timezone.utc)
                )
            )

        if not allowed:
            connection.execute(
                """INSERT INTO audit_logs
                   (actor_user_id, document_id, action, details)
                   VALUES (?, ?, ?, ?)""",
                (
                    current_user["id"], document_id,
                    "EDIT_DENIED", "Unauthorized edit attempt"
                )
            )
            connection.commit()
            raise HTTPException(
                status_code=403,
                detail="You do not have edit permission"
            )

        new_filename = (
            data.filename.strip()
            if data.filename is not None
            else document["filename"]
        )
        new_category = (
            data.category.strip()
            if data.category is not None
            else document["category"]
        )

        connection.execute(
            """UPDATE documents SET filename = ?, category = ?
               WHERE id = ?""",
            (new_filename, new_category, document_id)
        )

        connection.execute(
            """INSERT INTO audit_logs
               (actor_user_id, document_id, action, details)
               VALUES (?, ?, ?, ?)""",
            (
                current_user["id"], document_id,
                "EDIT", "Document metadata updated"
            )
        )
        connection.commit()

        return {"message": "Document details updated successfully"}
    finally:
        connection.close()

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()

    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        if (
            current_user["role"] != "admin"
            and document["owner_id"] != current_user["id"]
        ):
            connection.execute(
                """INSERT INTO audit_logs
                   (actor_user_id, document_id, action, details)
                   VALUES (?, ?, ?, ?)""",
                (
                    current_user["id"],
                    document_id,
                    "DELETE_DENIED",
                    "Unauthorized delete attempt"
                )
            )
            connection.commit()

            raise HTTPException(
                status_code=403,
                detail="Only the owner or admin can delete this document"
            )

        file_path = (
            STORAGE_DIR / document["stored_filename"]
        ).resolve()

        if (
            file_path.parent != STORAGE_DIR.resolve()
            or not file_path.is_file()
        ):
            raise HTTPException(
                status_code=404,
                detail="Stored document not found"
            )

        connection.execute(
            """INSERT INTO audit_logs
               (actor_user_id, document_id, action, details)
               VALUES (?, ?, ?, ?)""",
            (
                current_user["id"],
                document_id,
                "DELETE",
                "Document deleted"
            )
        )

        connection.execute(
            "DELETE FROM permissions WHERE document_id = ?",
            (document_id,)
        )

        connection.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,)
        )

        connection.commit()

        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            # Database record is already deleted.
            # Log/handle file cleanup separately in production.
            raise HTTPException(
                status_code=500,
                detail="Database record deleted, but file cleanup failed"
            )

        return {"message": "Document deleted successfully"}

    finally:
        connection.close()


@app.get("/admin/audit-logs")
def view_audit_logs(
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only admins can view audit logs"
        )

    connection = get_connection()
    try:
        logs = connection.execute(
            """SELECT a.id, a.actor_user_id, u.username,
                      a.document_id, a.action, a.details, a.created_at
               FROM audit_logs a
               LEFT JOIN users u ON u.id = a.actor_user_id
               ORDER BY a.id DESC
               LIMIT 500"""
        ).fetchall()

        return {"audit_logs": [dict(row) for row in logs]}
    finally:
        connection.close()

@app.get("/documents/search")
def search_documents(
    name: str = "",
    owner: str = "",
    category: str = "",
    date: str = "",
    current_user: dict = Depends(get_current_user)
):
    connection = get_connection()
    try:
        query = """
            SELECT DISTINCT
                d.id, d.filename, d.category,
                d.owner_id, u.username AS owner,
                d.uploaded_at
            FROM documents d
            JOIN users u ON d.owner_id = u.id
            LEFT JOIN permissions p
                ON p.document_id = d.id
                AND p.user_id = ?
            WHERE (
                ? = 'admin'
                OR d.owner_id = ?
                OR p.can_read = 1
            )
            AND d.filename LIKE ?
            AND u.username LIKE ?
            AND d.category LIKE ?
            AND date(d.uploaded_at) LIKE ?
            ORDER BY d.uploaded_at DESC
        """

        results = connection.execute(
            query,
            (
                current_user["id"],
                current_user["role"],
                current_user["id"],
                f"%{name}%",
                f"%{owner}%",
                f"%{category}%",
                f"%{date}%"
            )
        ).fetchall()

        return {"documents": [dict(row) for row in results]}
    finally:
        connection.close()
@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    connection = get_db_connection()

    try:
        document = connection.execute(
            "SELECT id, owner_id FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        if (
            current_user["role"] != "admin"
            and document["owner_id"] != current_user["id"]
        ):
            raise HTTPException(
                status_code=403,
                detail="You can delete only your own documents"
            )

        connection.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,)
        )
        connection.commit()

        return {"message": "Document deleted successfully"}

    finally:
        connection.close()
