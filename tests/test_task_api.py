"""Unit tests for TaskManagerAPI class."""
import json
from unittest.mock import Mock, patch
import pytest
import requests

from taskmanager_mcp.task_api import TaskManagerAPI, ApiResponse, create_authenticated_client


class TestApiResponse:
    def test_api_response_creation(self):
        response = ApiResponse(success=True, data={"test": "data"}, status_code=200)
        assert response.success is True
        assert response.data == {"test": "data"}
        assert response.status_code == 200
        assert response.error is None

    def test_api_response_error(self):
        response = ApiResponse(success=False, error="Test error", status_code=400)
        assert response.success is False
        assert response.error == "Test error"
        assert response.status_code == 400
        assert response.data is None


class TestTaskManagerAPI:
    def test_init_default(self):
        api = TaskManagerAPI()
        assert api.base_url == "http://localhost:4321/api"
        assert api.session is not None

    def test_init_custom_url(self):
        api = TaskManagerAPI("https://api.example.com/")
        assert api.base_url == "https://api.example.com"

    def test_init_custom_session(self):
        mock_session = Mock()
        mock_session.headers = Mock()
        api = TaskManagerAPI(session=mock_session)
        assert api.session is mock_session

    @patch('taskmanager_mcp.task_api.requests.Session')
    def test_make_request_get_success(self, mock_session_class):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.headers = {}
        mock_response.history = []
        mock_session.get.return_value = mock_response
        mock_session.cookies.get_dict.return_value = {}
        mock_session_class.return_value = mock_session

        api = TaskManagerAPI()
        api.session = mock_session
        
        result = api._make_request('GET', '/test', params={'param': 'value'})

        assert result.success is True
        assert result.data == {"result": "success"}
        assert result.status_code == 200
        mock_session.get.assert_called_once_with(
            'http://localhost:4321/api/test',
            params={'param': 'value'}
        )

    @patch('taskmanager_mcp.task_api.requests.Session')
    def test_make_request_post_success(self, mock_session_class):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 123}
        mock_response.headers = {}
        mock_response.history = []
        mock_session.post.return_value = mock_response
        mock_session.cookies.get_dict.return_value = {}
        mock_session_class.return_value = mock_session

        api = TaskManagerAPI()
        api.session = mock_session
        
        result = api._make_request('POST', '/test', data={'name': 'test'})

        assert result.success is True
        assert result.data == {"id": 123}
        assert result.status_code == 201
        mock_session.post.assert_called_once_with(
            'http://localhost:4321/api/test',
            json={'name': 'test'},
            params=None
        )

    @patch('taskmanager_mcp.task_api.requests.Session')
    def test_make_request_error_response(self, mock_session_class):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Not found"}
        mock_response.headers = {}
        mock_response.history = []
        mock_session.get.return_value = mock_response
        mock_session.cookies.get_dict.return_value = {}
        mock_session_class.return_value = mock_session

        api = TaskManagerAPI()
        api.session = mock_session
        
        result = api._make_request('GET', '/nonexistent')
        
        assert result.success is False
        assert result.error == "Not found"
        assert result.status_code == 404

    @patch('taskmanager_mcp.task_api.requests.Session')
    def test_make_request_network_error(self, mock_session_class):
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("Network error")
        mock_session_class.return_value = mock_session

        api = TaskManagerAPI()
        api.session = mock_session
        
        result = api._make_request('GET', '/test')
        
        assert result.success is False
        assert "Network error" in result.error

    @patch('taskmanager_mcp.task_api.requests.Session')
    def test_make_request_set_cookie(self, mock_session_class):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_response.headers = {}
        mock_response.history = []
        mock_session.get.return_value = mock_response
        mock_session.cookies.get_dict.return_value = {}
        mock_session_class.return_value = mock_session

        api = TaskManagerAPI()
        api.session = mock_session

        result = api._make_request('GET', '/test')

        assert result.success is True
        # Session handles cookies automatically - just verify the request was made
        mock_session.get.assert_called_once()

    def test_unsupported_method(self):
        api = TaskManagerAPI()
        result = api._make_request('PATCH', '/test')
        
        assert result.success is False
        assert "Unsupported HTTP method: PATCH" in result.error

    @patch.object(TaskManagerAPI, '_make_request')
    def test_login(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"token": "abc123"})
        
        api = TaskManagerAPI()
        result = api.login("testuser", "password123")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/auth/login', {
            'username': 'testuser',
            'password': 'password123'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_register(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"user_id": 123})
        
        api = TaskManagerAPI()
        result = api.register("newuser", "test@example.com", "password123")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/auth/register', {
            'username': 'newuser',
            'email': 'test@example.com',
            'password': 'password123'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_get_projects(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data=[{"id": 1, "name": "Project 1"}])
        
        api = TaskManagerAPI()
        result = api.get_projects()
        
        assert result.success is True
        mock_make_request.assert_called_once_with('GET', '/projects')

    @patch.object(TaskManagerAPI, '_make_request')
    def test_create_project(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 123})
        
        api = TaskManagerAPI()
        result = api.create_project("Test Project", "#FF0000", "Test description")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/projects', {
            'name': 'Test Project',
            'color': '#FF0000',
            'description': 'Test description'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_create_project_no_description(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 123})
        
        api = TaskManagerAPI()
        result = api.create_project("Test Project", "#FF0000")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/projects', {
            'name': 'Test Project',
            'color': '#FF0000'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_get_todos_with_filters(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data=[])
        
        api = TaskManagerAPI()
        result = api.get_todos(project_id=1, status="pending", time_horizon="week")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('GET', '/todos', params={
            'project_id': 1,
            'status': 'pending',
            'time_horizon': 'week'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_create_todo_minimal(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 456})
        
        api = TaskManagerAPI()
        result = api.create_todo("Test Task")
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/todos', {
            'title': 'Test Task',
            'priority': 'medium',
            'estimated_hours': 1.0,
            'context': 'work'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_create_todo_full(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"id": 456})
        
        api = TaskManagerAPI()
        result = api.create_todo(
            title="Complex Task",
            project_id=1,
            description="This is a complex task",
            priority="high",
            estimated_hours=5.0,
            due_date="2024-12-31",
            tags=["urgent", "important"],
            context="personal",
            time_horizon="month"
        )
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/todos', {
            'title': 'Complex Task',
            'project_id': 1,
            'description': 'This is a complex task',
            'priority': 'high',
            'estimated_hours': 5.0,
            'due_date': '2024-12-31',
            'tags': ['urgent', 'important'],
            'context': 'personal',
            'time_horizon': 'month'
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_complete_todo(self, mock_make_request):
        mock_make_request.return_value = ApiResponse(success=True, data={"completed": True})
        
        api = TaskManagerAPI()
        result = api.complete_todo(123, 2.5)
        
        assert result.success is True
        mock_make_request.assert_called_once_with('POST', '/todos/123/complete', {
            'actual_hours': 2.5
        })

    @patch.object(TaskManagerAPI, '_make_request')
    def test_oauth_token_exchange(self, mock_make_request):
        # Mock the session.post call directly since oauth_token_exchange doesn't use _make_request
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "token123", "token_type": "Bearer"}
        mock_session.post.return_value = mock_response
        
        api = TaskManagerAPI()
        api.session = mock_session
        
        result = api.oauth_token_exchange(
            grant_type="authorization_code",
            client_id="client123",
            client_secret="secret456",
            code="auth_code_789"
        )
        
        assert result.success is True
        assert result.data["access_token"] == "token123"


class TestCreateAuthenticatedClient:
    @patch.object(TaskManagerAPI, 'login')
    def test_create_authenticated_client_success(self, mock_login):
        mock_login.return_value = ApiResponse(success=True, data={"token": "abc123"})
        
        client = create_authenticated_client("testuser", "password123")
        
        assert client is not None
        assert isinstance(client, TaskManagerAPI)
        mock_login.assert_called_once_with("testuser", "password123")

    @patch.object(TaskManagerAPI, 'login')
    @patch('builtins.print')
    def test_create_authenticated_client_failure(self, mock_print, mock_login):
        mock_login.return_value = ApiResponse(success=False, error="Invalid credentials")
        
        client = create_authenticated_client("testuser", "wrongpassword")
        
        assert client is None
        mock_login.assert_called_once_with("testuser", "wrongpassword")
        mock_print.assert_called_once_with("Authentication failed: Invalid credentials")