from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict
import os

app = FastAPI()

# In-memory storage for demo purposes
fake_users_db: Dict[int, Dict[str, str]] = {
    1010: {"username": "admin", "password": "FGMGOGJdf4qQqd@a", "id": 1010},
    2: {"username": "hacker", "password": "123pass123", "id": 2}
}

FLAG = "SECURINETS={SP1D3RS_1D0R}"

# Path to the HTML file
login_file_path = os.path.join(os.path.dirname(__file__), "login.html")
profile_file_path = os.path.join(os.path.dirname(__file__), "profile.html")
signup_file_path = os.path.join(os.path.dirname(__file__), "signup.html")
cp_file_path = os.path.join(os.path.dirname(__file__), "change_password.html")

def readFile(html_file_path):
    with open(html_file_path, "r") as f:
        content = f.read()
    return content

# Read the content of the HTML file and return it
@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        content = readFile(login_file_path)
        # Convert users to an HTML-friendly format
        users_html = ''.join(
            f'<li>Username: {user["username"]}</li>' for user in fake_users_db.values())
        # Embed the user data into the HTML by replacing a placeholder
        content = content.replace("{{ users }}", users_html)

        return HTMLResponse(content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error loading login page")

# Dependency to get current user
def get_current_user(request: Request):
    user_id = request.cookies.get("user_id")
    if not user_id or int(user_id) not in fake_users_db:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return fake_users_db[int(user_id)]

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
async def login(data: LoginRequest):
    for user in fake_users_db.values():
        if user["username"] == data.username and user["password"] == data.password:
            response = JSONResponse(content={"message": "Login successful", "user_id": user["id"]})
            response.set_cookie(key="user_id", value=str(user["id"]))
            return response
    raise HTTPException(status_code=400, detail="Invalid username or password")

@app.get("/signup")
async def signup():
    try:
        content = readFile(signup_file_path)

        return HTMLResponse(content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error loading login page")
    # return {"username": current_user["username"], "user_id": current_user["id"]}

@app.post("/sign-up")
async def change_password(user_data: LoginRequest):
    # Vulnerable to IDOR as it allows any user to specify a `user_id`
    print(user_data)
    # Check if the username already exists
    for user in fake_users_db.values():
        if user["username"] == user_data.username:
            raise HTTPException(status_code=400, detail="Username already exists")

    # Generate a new user ID (this can be done by incrementing the largest ID or another method)
    new_user_id = max(fake_users_db.keys()) + 1 if fake_users_db else 1

    # Add the new user to the fake_users_db
    fake_users_db[new_user_id] = {
        "username": user_data.username,
        "password": user_data.password,
        "id": new_user_id,
    }
    return {"message": "Password changed successfully"}

    # raise HTTPException(status_code=404, detail="User not found")


# Profile endpoint
@app.get("/profile")
async def profile(current_user: Dict = Depends(get_current_user)):
    try:
        content = readFile(profile_file_path)

        # Inject data into the HTML (e.g., username from the current user)

        if current_user['id'] == 1010:
            content = content.replace("{{ username }}", FLAG)
        else:
            content = content.replace("{{ username }}", current_user["username"])

        return HTMLResponse(content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error loading login page")
    # return {"username": current_user["username"], "user_id": current_user["id"]}

# Change password endpoint with IDOR vulnerability
class ChangePasswordRequest(BaseModel):
    user_id: int
    new_password: str
    confirm_password: str

@app.get("/resetpassword")
async def reset_password(current_user: Dict = Depends(get_current_user)):
    try:
        content = readFile(cp_file_path)
        # print(current_user["id"])
        content = content.replace("{{ id }}", str(current_user["id"]))

        return HTMLResponse(content=content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error loading login page")

@app.post("/change-password")
async def change_password(data: ChangePasswordRequest):
    # Vulnerable to IDOR as it allows any user to specify a `user_id`
    if data.new_password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    user = fake_users_db.get(data.user_id)
    if user:
        user["password"] = data.new_password
        return {"message": "Password changed successfully"}
    raise HTTPException(status_code=404, detail="User not found")
