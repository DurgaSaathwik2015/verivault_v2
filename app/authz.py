
def authorize(user, doc, action):
    """
    Centralized authorization for TrustVault.

    Supported actions:
        read, edit, delete, share

    Returns:
        True  - Access permitted
        False - Access denied
    """

    # Deny if user or document does not exist.
    if user is None or doc is None:
        return False

    # Deny inactive accounts.
    if not user.is_active:
        return False

    # Validate requested action.
    allowed_actions = {"read", "edit", "delete", "share"}

    if action not in allowed_actions:
        return False

    # Document owner has implicit full rights.
    if doc.owner_id == user.id:
        return True

    # Admin does not automatically get document access.
    # Least privilege: admin must also receive a grant.

    # Look up permission from the database on every request.
    from app.models import Grant

    grant = Grant.query.filter_by(
        document_id=doc.id,
        user_id=user.id
    ).first()

    if grant is None:
        return False

    # Read permission allows reading only.
    if action == "read":
        return grant.permission in {"read", "edit"}

    # Edit permission allows editing and reading.
    if action == "edit":
        return grant.permission == "edit"

    # Only owners can delete or share.
    # Other users cannot delete or share through a grant.
    if action in {"delete", "share"}:
        return False

    # Deny by default.
    return False
