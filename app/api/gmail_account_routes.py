from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.gmail.account_manager import (
    GmailAccountError,
    connect_new_account,
    disconnect_account,
    list_accounts,
    set_account_active,
    set_primary_account,
)


router = APIRouter(
    prefix="/gmail-accounts",
    tags=["Gmail Account Management"],
)


@router.get("")
def retrieve_accounts():
    return {
        "accounts": list_accounts()
    }


@router.post("/connect")
def connect_account():
    try:
        return connect_new_account()

    except GmailAccountError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Gmail account connection failed: "
                f"{error}"
            ),
        ) from error


@router.post("/{account_id}/activate")
def activate_account(
    account_id: int,
):
    try:
        return set_account_active(
            account_id,
            True,
        )

    except GmailAccountError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error


@router.post("/{account_id}/deactivate")
def deactivate_account(
    account_id: int,
):
    try:
        return set_account_active(
            account_id,
            False,
        )

    except GmailAccountError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error


@router.post("/{account_id}/primary")
def make_primary_account(
    account_id: int,
):
    try:
        return set_primary_account(
            account_id
        )

    except GmailAccountError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error


@router.delete("/{account_id}")
def remove_account(
    account_id: int,
):
    try:
        return disconnect_account(
            account_id
        )

    except GmailAccountError as error:
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error
