import uuid

from pydantic import BaseModel


class NewsMention(BaseModel):
    title: str
    link: str
    source: str
    published_at: str | None
    description: str | None


class VendorNewsMention(NewsMention):
    vendor_id: uuid.UUID
    vendor_name: str
