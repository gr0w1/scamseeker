from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

app = FastAPI()

notes = []
next_id = 1


class Note(BaseModel):
    id: int
    text: str
    tags: List[str]
    created_at: datetime


class NoteIn(BaseModel):
    text: Optional[str] = None
    tags: Optional[List[str]] = None


def check(text=None, tags=None):
    if text is not None and (not text or len(text) > 200):
        raise HTTPException(400)
    if tags is not None:
        if len(tags) > 5:
            raise HTTPException(400)
        for t in tags:
            if not t or len(t) > 20:
                raise HTTPException(400)


@app.post("/notes", response_model=Note, status_code=201)
def create(note: NoteIn):
    global next_id
    check(note.text, note.tags)
    n = {
        "id": next_id,
        "text": note.text,
        "tags": note.tags or [],
        "created_at": datetime.now()
    }
    notes.append(n)
    next_id += 1
    return n


@app.get("/notes", response_model=List[Note])
def get_all(tag: Optional[str] = Query(None)):
    return [n for n in notes if tag in n["tags"]] if tag else notes


@app.get("/notes/{id}", response_model=Note)
def get_one(id: int):
    for n in notes:
        if n["id"] == id:
            return n
    raise HTTPException(404)


@app.patch("/notes/{id}", response_model=Note)
def update(id: int, data: NoteIn):
    for n in notes:
        if n["id"] == id:
            check(data.text, data.tags)
            if data.text is not None:
                n["text"] = data.text
            if data.tags is not None:
                n["tags"] = data.tags
            return n
    raise HTTPException(404)


@app.delete("/notes/{id}", status_code=204)
def delete(id: int):
    for i, n in enumerate(notes):
        if n["id"] == id:
            notes.pop(i)
            return
    raise HTTPException(404)



import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)