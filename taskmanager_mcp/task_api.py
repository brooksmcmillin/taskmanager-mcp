import logging
import os
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()
CLIENT_ID = ""
CLIENT_SECRET = ""

logger = logging.getLogger(__name__)


@dataclass
class ApiResponse:
    success: bool
    data: Any | None = None
    error: str | None = None
    status_code: int | None = None


class TaskManagerAPI:
    def __init__(
        self,
        base_url: str = "http://localhost:4321/api",
        session: requests.Session | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> ApiResponse:
        url = f"{self.base_url}{endpoint}"

        try:
            if method.upper() == "GET":
                response = self.session.get(url, params=params)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data, params=params)
            elif method.upper() == "PUT":
                response = self.session.put(url, json=data, params=params)
            elif method.upper() == "DELETE":
                response = self.session.delete(url, params=params)
            else:
                return ApiResponse(success=False, error=f"Unsupported HTTP method: {method}")

            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Session cookies after request: {self.session.cookies.get_dict()}")

            # Log if we got redirected (which would indicate auth failure)
            if response.history:
                logger.warning(
                    f"Request was redirected: {[r.status_code for r in response.history]} -> {response.status_code}"
                )
                logger.warning(f"Final URL: {response.url}")

            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get("error", f"HTTP {response.status_code}")
                except JSONDecodeError:
                    error_message = f"HTTP {response.status_code}: {response.text}"

                return ApiResponse(
                    success=False, error=error_message, status_code=response.status_code
                )

            try:
                json_data = response.json()
            except JSONDecodeError:
                json_data = None

            return ApiResponse(success=True, data=json_data, status_code=response.status_code)

        except requests.exceptions.RequestException as e:
            return ApiResponse(success=False, error=str(e))

    def login(self, username: str, password: str) -> ApiResponse:
        return self._make_request(
            "POST", "/auth/login", {"username": username, "password": password}
        )

    def register(self, username: str, email: str, password: str) -> ApiResponse:
        return self._make_request(
            "POST", "/auth/register", {"username": username, "email": email, "password": password}
        )

    def logout(self) -> ApiResponse:
        return self._make_request("POST", "/auth/logout")

    def get_current_user(self) -> ApiResponse:
        return self._make_request("GET", "/auth/me")

    def get_projects(self) -> ApiResponse:
        return self._make_request("GET", "/projects")

    def create_project(self, name: str, color: str, description: str | None = None) -> ApiResponse:
        data = {"name": name, "color": color}
        if description is not None:
            data["description"] = description
        return self._make_request("POST", "/projects", data)

    def get_project(self, project_id: int) -> ApiResponse:
        return self._make_request("GET", f"/projects/{project_id}")

    def update_project(
        self,
        project_id: int,
        name: str | None = None,
        color: str | None = None,
        description: str | None = None,
    ) -> ApiResponse:
        data = {}
        if name is not None:
            data["name"] = name
        if color is not None:
            data["color"] = color
        if description is not None:
            data["description"] = description
        return self._make_request("PUT", f"/projects/{project_id}", data)

    def get_todos(
        self,
        project_id: int | None = None,
        status: str | None = None,
        time_horizon: str | None = None,
    ) -> ApiResponse:
        params: dict[str, Any] = {}
        if project_id is not None:
            params["project_id"] = project_id
        if status is not None:
            params["status"] = status
        if time_horizon is not None:
            params["time_horizon"] = time_horizon
        return self._make_request("GET", "/todos", params=params)

    def create_todo(
        self,
        title: str,
        project_id: int | None = None,
        description: str | None = None,
        priority: str = "medium",
        estimated_hours: float = 1.0,
        due_date: str | None = None,
        tags: list[str] | None = None,
        context: str = "work",
        time_horizon: str | None = None,
    ) -> ApiResponse:
        data = {
            "title": title,
            "priority": priority,
            "estimated_hours": estimated_hours,
            "context": context,
        }
        if project_id is not None:
            data["project_id"] = project_id
        if description is not None:
            data["description"] = description
        if due_date is not None:
            data["due_date"] = due_date
        if tags is not None:
            data["tags"] = tags
        if time_horizon is not None:
            data["time_horizon"] = time_horizon
        return self._make_request("POST", "/todos", data)

    def get_todo(self, todo_id: int) -> ApiResponse:
        return self._make_request("GET", f"/todos/{todo_id}")

    def update_todo(
        self,
        todo_id: int,
        title: str | None = None,
        project_id: int | None = None,
        description: str | None = None,
        priority: str | None = None,
        estimated_hours: float | None = None,
        status: str | None = None,
        due_date: str | None = None,
        tags: list[str] | None = None,
        context: str | None = None,
        time_horizon: str | None = None,
    ) -> ApiResponse:
        data: dict[str, Any] = {}
        if title is not None:
            data["title"] = title
        if project_id is not None:
            data["project_id"] = project_id
        if description is not None:
            data["description"] = description
        if priority is not None:
            data["priority"] = priority
        if estimated_hours is not None:
            data["estimated_hours"] = estimated_hours
        if status is not None:
            data["status"] = status
        if due_date is not None:
            data["due_date"] = due_date
        if tags is not None:
            data["tags"] = tags
        if context is not None:
            data["context"] = context
        if time_horizon is not None:
            data["time_horizon"] = time_horizon
        return self._make_request("PUT", f"/todos/{todo_id}", data)

    def update_todo_bulk(self, todo_id: int, **kwargs: Any) -> ApiResponse:
        data = {"id": todo_id}
        data.update(kwargs)
        return self._make_request("PUT", "/todos", data)

    def complete_todo(self, todo_id: int, actual_hours: float) -> ApiResponse:
        return self._make_request(
            "POST", f"/todos/{todo_id}/complete", {"actual_hours": actual_hours}
        )

    def get_reports(
        self,
        start_date: str,
        end_date: str,
        status: str = "pending",
        time_horizon: str | None = None,
    ) -> ApiResponse:
        params = {"start_date": start_date, "end_date": end_date, "status": status}
        if time_horizon is not None:
            params["time_horizon"] = time_horizon
        return self._make_request("GET", "/reports", params=params)

    def get_oauth_clients(self) -> ApiResponse:
        return self._make_request("GET", "/oauth/clients")

    def create_oauth_client(
        self,
        name: str,
        redirect_uris: list[str],
        grant_types: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> ApiResponse:
        data = {"name": name, "redirectUris": redirect_uris}
        if grant_types is not None:
            data["grantTypes"] = grant_types
        if scopes is not None:
            data["scopes"] = scopes
        return self._make_request("POST", "/oauth/clients", data)

    def oauth_token_exchange(
        self, grant_type: str, client_id: str, client_secret: str, **kwargs: Any
    ) -> ApiResponse:
        data = {"grant_type": grant_type, "client_id": client_id, "client_secret": client_secret}
        data.update(kwargs)

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self.session.post(f"{self.base_url}/oauth/token", data=data, headers=headers)

        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_message = error_data.get(
                    "error_description", error_data.get("error", f"HTTP {response.status_code}")
                )
            except JSONDecodeError:
                error_message = f"HTTP {response.status_code}: {response.text}"

            return ApiResponse(success=False, error=error_message, status_code=response.status_code)

        try:
            json_data = response.json()
        except JSONDecodeError:
            json_data = None

        return ApiResponse(success=True, data=json_data, status_code=response.status_code)


def create_authenticated_client(
    username: str, password: str, base_url: str = "http://localhost:4321/api"
) -> TaskManagerAPI | None:
    logger.info(f"Attempting to authenticate with backend at {base_url}")
    # Username is potentially sensitive; do not log in clear text.

    client = TaskManagerAPI(base_url)
    response = client.login(username, password)

    if response.success:
        logger.info("Authentication successful")
        logger.debug(f"Session cookies after login: {client.session.cookies.get_dict()}")
        return client
    else:
        logger.error(f"Authentication failed: {response.error}")
        print(f"Authentication failed: {response.error}")
        return None


if __name__ == "__main__":
    CLIENT_ID = os.environ["TASKMANAGER_CLIENT_ID"]
    CLIENT_SECRET = os.environ["TASKMANAGER_CLIENT_SECRET"]
    api = TaskManagerAPI()
    response = api.login(CLIENT_ID, CLIENT_SECRET)
    print(response)
    if not response.success:
        print("Login Failed...")
    else:
        projects = api.get_projects()
        print(projects)
