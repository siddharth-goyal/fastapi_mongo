from datetime import datetime
from sqlite3 import Date, DateFromTicks
from tokenize import group
from pydantic import BaseModel

class Todo(BaseModel):
    name: str
    description: str
    completed: bool
    date: datetime
    group : int