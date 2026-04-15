import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from config import DOCS_PASSWORD, DOCS_USER, MODE
from database import (
    create_todo,
    create_user,
    delete_todo,
    find_user_by_username,
    get_todo,
    init_db,
    list_todos,
    update_todo,
)
from models import LoginRequest, Message, TodoCreate, TodoOut, TodoUpdate, Token, User, UserInDB
from rate_limiter import enforce_rate_limit
from security import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_password_hash,
    require_roles,
    verify_password,
)


basic_scheme = HTTPBasic()

ROLE_PERMISSIONS = {
    "admin": {"create", "read", "update", "delete"},
    "user": {"read", "update"},
    "guest": {"read"},
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="KR3 FastAPI Auth and CRUD",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _constant_time_equal(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def docs_auth(credentials: HTTPBasicCredentials = Depends(basic_scheme)) -> bool:
    valid_username = _constant_time_equal(credentials.username, DOCS_USER)
    valid_password = _constant_time_equal(credentials.password, DOCS_PASSWORD)

    if not (valid_username and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid documentation credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


def auth_user(credentials: HTTPBasicCredentials = Depends(basic_scheme)) -> UserInDB:
    user = find_user_by_username(credentials.username)
    if user is None or not verify_password(credentials.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return UserInDB(
        username=user["username"],
        hashed_password=user["password"],
        role=user["role"],
    )


if MODE == "DEV":

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json(_: bool = Depends(docs_auth)):
        return get_openapi(title=app.title, version=app.version, routes=app.routes)

    @app.get("/docs", include_in_schema=False)
    async def swagger_docs(_: bool = Depends(docs_auth)):
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{app.title} - Swagger UI",
        )


@app.get("/", response_model=Message)
async def root() -> Message:
    return Message(message=f"Application is running in {MODE} mode")


@app.post("/register", response_model=Message, status_code=status.HTTP_201_CREATED)
async def register(user: User, request: Request) -> Message:
    if find_user_by_username(user.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )

    enforce_rate_limit(request, "register", limit=1, window_seconds=60)
    password_hash = get_password_hash(user.password)
    create_user(user.username, password_hash, user.role)
    return Message(message="New user created")


@app.get("/login")
async def login_basic(current_user: UserInDB = Depends(auth_user)):
    return {
        "message": f"Welcome, {current_user.username}!",
        "secret_message": "You got my secret, welcome",
    }


@app.post("/login", response_model=Token)
async def login_jwt(credentials: LoginRequest, request: Request) -> Token:
    user = find_user_by_username(credentials.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    enforce_rate_limit(
        request,
        "login",
        limit=5,
        window_seconds=60,
        identifier=credentials.username,
    )

    authenticated_user = authenticate_user(credentials.username, credentials.password)
    if authenticated_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed",
        )

    return Token(
        access_token=create_access_token(
            authenticated_user["username"],
            authenticated_user["role"],
        ),
        token_type="bearer",
    )


@app.get("/protected_resource")
async def protected_resource(_: UserInDB = Depends(require_roles("admin", "user"))):
    return {"message": "Access granted"}


@app.get("/rbac/read")
async def rbac_read(current_user: UserInDB = Depends(get_current_user)):
    return {
        "message": "Read access granted",
        "role": current_user.role,
        "permissions": sorted(ROLE_PERMISSIONS[current_user.role]),
    }


@app.post("/rbac/create")
async def rbac_create(_: UserInDB = Depends(require_roles("admin"))):
    return {"message": "Create access granted"}


@app.put("/rbac/update")
async def rbac_update(_: UserInDB = Depends(require_roles("admin", "user"))):
    return {"message": "Update access granted"}


@app.delete("/rbac/delete")
async def rbac_delete(_: UserInDB = Depends(require_roles("admin"))):
    return {"message": "Delete access granted"}


@app.post("/todos", response_model=TodoOut, status_code=status.HTTP_201_CREATED)
async def add_todo(todo: TodoCreate) -> TodoOut:
    return TodoOut(**create_todo(todo.title, todo.description))


@app.get("/todos", response_model=list[TodoOut])
async def read_todos() -> list[TodoOut]:
    return [TodoOut(**todo) for todo in list_todos()]


@app.get("/todos/{todo_id}", response_model=TodoOut)
async def read_todo(todo_id: int) -> TodoOut:
    todo = get_todo(todo_id)
    if todo is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )
    return TodoOut(**todo)


@app.put("/todos/{todo_id}", response_model=TodoOut)
async def edit_todo(todo_id: int, todo: TodoUpdate) -> TodoOut:
    updated = update_todo(
        todo_id,
        title=todo.title,
        description=todo.description,
        completed=todo.completed,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )
    return TodoOut(**updated)


@app.delete("/todos/{todo_id}", response_model=Message)
async def remove_todo(todo_id: int) -> Message:
    if not delete_todo(todo_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found",
        )
    return Message(message="Todo deleted successfully")
