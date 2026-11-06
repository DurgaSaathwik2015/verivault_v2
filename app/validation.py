from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "doc",
    "docx",
    "png",
    "jpg",
    "jpeg"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Expected file signatures.
FILE_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "doc": [bytes.fromhex("D0CF11E0A1B11AE1")],
    "docx": [b"PK\x03\x04"],
    "png": [bytes.fromhex("89504E470D0A1A0A")],
    "jpg": [bytes.fromhex("FFD8FF")],
    "jpeg": [bytes.fromhex("FFD8FF")]
}


def validate_upload(file):

    if not file:
        return False, "No file provided"

    original_filename = file.filename or ""

    if not original_filename.strip():
        return False, "Filename is required"

    safe_name = secure_filename(original_filename)

    if not safe_name or "." not in safe_name:
        return False, "Invalid filename"

    extension = safe_name.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False, "File type not allowed"

    try:
        file.stream.seek(0, 2)
        file_size = file.stream.tell()
        file.stream.seek(0)

        if file_size == 0:
            return False, "Empty files are not allowed"

        if file_size > MAX_FILE_SIZE:
            return False, "File exceeds the 10 MB limit"

        # Read the beginning of the file for content validation.
        file_header = file.stream.read(16)
        file.stream.seek(0)

    except (OSError, AttributeError):
        return False, "Unable to read uploaded file"

    # Validate actual file signatures.
    if extension in FILE_SIGNATURES:

        valid_signature = any(
            file_header.startswith(signature)
            for signature in FILE_SIGNATURES[extension]
        )

        if not valid_signature:
            return False, "File content does not match its extension"

    # TXT files do not have a fixed magic-byte signature.
    elif extension == "txt":

        try:
            sample = file.stream.read(4096)
            sample.decode("utf-8")

            if b"\x00" in sample:
                return False, "Invalid text file content"

        except UnicodeDecodeError:
            return False, "Text file must contain valid UTF-8 content"

        finally:
            file.stream.seek(0)

    return True, {
        "original_filename": safe_name,
        "extension": extension,
        "size": file_size
    }