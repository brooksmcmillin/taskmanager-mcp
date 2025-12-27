"""Unit tests for TaskManagerClient class from taskmanager_sdk."""

from unittest.mock import Mock, patch

import pytest
import requests
from taskmanager_sdk import (
    ApiResponse,
    AuthenticationError,
    NetworkError,
    NotFoundError,
    TaskManagerClient,
    create_authenticated_client,
)

# Backwards compatibility alias (as exported from taskmanager_mcp)
TaskManagerAPI = TaskManagerClient


class TestApiResponse:
    def test_api_response_creation(self) -> None:
        response = ApiResponse(success=True, data={"test": "data"}, status_code=200)
        assert response.success is True
        assert response.data == {"test": "data"}
        assert response.status_code == 200
        assert response.error is None

    def test_api_response_error(self) -> None:
        response = ApiResponse(success=False, error="Test error", status_code=400)
        assert response.success is False
        assert response.error == "Test error"
        assert response.status_code == 400
        assert response.data is None


class TestTaskManagerAPI:
    def test_init_default(self) -> None:
        api = TaskManagerAPI()
        assert api.base_url == "http://localhost:4321/api"
        assert api.session is not None

    def test_init_custom_url(self) -> None:
        api = TaskManagerAPI("https://api.example.com/")
        assert api.base_url == "https://api.example.com"

    def test_init_custom_session(self) -> None:
        mock_session = Mock()
        mock_session.headers = Mock()
        api = TaskManagerAPI(session=mock_session)
        assert api.session is mock_session

    def test_make_request_get_success(self) -> None:
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.headers = {}
        mock_session.get.return_value = mock_response

        api = TaskManagerAPI()
        api.session = mock_session

        result = api._make_request("GET", "/test", params={"param": "value"})

        assert result.success is True
        assert result.data == {"result": "success"}
        assert result.status_code == 200
        # SDK uses cookies parameter
        mock_session.get.assert_called_once()

    def test_make_request_post_success(self) -> None:
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_response.headers = {}
        mock_session.post.return_value = mock_response

        api = TaskManagerAPI()
        api.session = mock_session

        result = api._make_request("POST", "/test", data={"name": "test"})

        assert result.success is True
        assert result.data == {"id": 123}
        assert result.status_code == 201
        mock_session.post.assert_called_once()

    def test_make_request_error_response_raises_exception(self) -> None:
        """SDK raises NotFoundError for 404 responses."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not found"}
        mock_response.headers = {}
        mock_session.get.return_value = mock_response

        api = TaskManagerAPI()
        api.session = mock_session

        with pytest.raises(NotFoundError):
            api._make_request("GET", "/nonexistent")

    def test_make_request_network_error_raises_exception(self) -> None:
        """SDK raises NetworkError for connection failures."""
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Network error")

        api = TaskManagerAPI()
        api.session = mock_session

        with pytest.raises(NetworkError):
            api._make_request("GET", "/test")

    def test_make_request_set_cookie(self) -> None:
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_response.headers = {"set-cookie": "session=abc123; Path=/"}
        mock_session.get.return_value = mock_response

        api = TaskManagerAPI()
        api.session = mock_session

        result = api._make_request("GET", "/test")

        assert result.success is True
        # SDK stores cookies in api.cookies dict
        assert api.cookies.get("session") == "abc123"

    def test_unsupported_method(self) -> None:
        api = TaskManagerAPI()
        result = api._make_request("PATCH", "/test")

        assert result.success is False
        assert "Unsupported HTTP method: PATCH" in result.error  # type: ignore

    @patch.object(TaskManagerAPI, "_make_request")
    def test_login(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"token": "abc123"})

        api = TaskManagerAPI()
        result = api.login("testuser", "password123")

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST", "/auth/login", {"username": "testuser", "password": "password123"}
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_register(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"user_id": 123})

        api = TaskManagerAPI()
        result = api.register("newuser", "test@example.com", "password123")

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST",
            "/auth/register",
            {"username": "newuser", "email": "test@example.com", "password": "password123"},
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_get_projects(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(
            success=True, data=[{"id": 1, "name": "Project 1"}]
        )

        api = TaskManagerAPI()
        result = api.get_projects()

        assert result.success is True
        mock_make_request.assert_called_once_with("GET", "/projects")

    @patch.object(TaskManagerAPI, "_make_request")
    def test_create_project(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 123})

        api = TaskManagerAPI()
        # SDK signature: create_project(name, description=None, color=None)
        result = api.create_project("Test Project", "Test description", "#FF0000")

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST",
            "/projects",
            {"name": "Test Project", "description": "Test description", "color": "#FF0000"},
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_create_project_no_description(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 123})

        api = TaskManagerAPI()
        # SDK signature: create_project(name, description=None, color=None)
        result = api.create_project("Test Project", color="#FF0000")

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST", "/projects", {"name": "Test Project", "color": "#FF0000"}
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_get_todos_with_filters(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data=[])

        api = TaskManagerAPI()
        # SDK signature: get_todos(project_id, status, start_date, end_date, category, limit)
        result = api.get_todos(project_id=1, status="pending", category="work")

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "GET", "/todos", params={"project_id": 1, "status": "pending", "category": "work"}
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_create_todo_minimal(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 456})

        api = TaskManagerAPI()
        result = api.create_todo("Test Task")

        assert result.success is True
        # SDK only includes title and priority by default
        mock_make_request.assert_called_once_with(
            "POST",
            "/todos",
            {"title": "Test Task", "priority": "medium"},
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_create_todo_full(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 456})

        api = TaskManagerAPI()
        # SDK signature: create_todo(title, project_id, description, category, priority, estimated_hours, due_date, tags)
        result = api.create_todo(
            title="Complex Task",
            project_id=1,
            description="This is a complex task",
            category="work",
            priority="high",
            estimated_hours=5.0,
            due_date="2024-12-31",
            tags=["urgent", "important"],
        )

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST",
            "/todos",
            {
                "title": "Complex Task",
                "project_id": 1,
                "description": "This is a complex task",
                "category": "work",
                "priority": "high",
                "estimated_hours": 5.0,
                "due_date": "2024-12-31",
                "tags": ["urgent", "important"],
            },
        )

    @patch.object(TaskManagerAPI, "_make_request")
    def test_complete_todo(self, mock_make_request: Mock) -> None:
        mock_make_request.return_value = ApiResponse(success=True, data={"completed": True})

        api = TaskManagerAPI()
        result = api.complete_todo(123, 2.5)

        assert result.success is True
        mock_make_request.assert_called_once_with(
            "POST", "/todos/123/complete", {"actual_hours": 2.5}
        )

    # Note: oauth_token_exchange was in the old local implementation but not in the SDK
    # OAuth token exchange is now handled through the SDK's OAuth flow methods


class TestCreateAuthenticatedClient:
    @patch.object(TaskManagerClient, "login")
    def test_create_authenticated_client_success(self, mock_login: Mock) -> None:
        mock_login.return_value = ApiResponse(success=True, data={"token": "abc123"})

        client = create_authenticated_client("testuser", "password123")

        assert client is not None
        assert isinstance(client, TaskManagerClient)
        mock_login.assert_called_once_with("testuser", "password123")

    @patch.object(TaskManagerClient, "login")
    def test_create_authenticated_client_failure(self, mock_login: Mock) -> None:
        """SDK raises AuthenticationError on login failure."""
        mock_login.return_value = ApiResponse(success=False, error="Invalid credentials")

        with pytest.raises(AuthenticationError):
            create_authenticated_client("testuser", "wrongpassword")
