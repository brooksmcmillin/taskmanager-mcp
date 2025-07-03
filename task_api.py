import os
from dataclasses import dataclass
from typing import Any, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
# CLIENT_ID = os.environ["TASK_API_CLIENT_ID"]
# CLIENT_SECRET = os.environ["TASK_API_CLIENT_SECRET"]

@dataclass
class ApiResponse:
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    status_code: Optional[int] = None


class TaskManagerAPI:
    def __init__(self, base_url: str = "http://localhost:4321/api", session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self.cookies = {}

    def _make_request(self, method: str, endpoint: str, data: Optional[dict] = None, params: Optional[dict] = None) -> ApiResponse:
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, cookies=self.cookies)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, cookies=self.cookies)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, params=params, cookies=self.cookies)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, params=params, cookies=self.cookies)
            else:
                return ApiResponse(success=False, error=f"Unsupported HTTP method: {method}")

            # print(f"Response ({response.status_code}): {response.text}")
            # print(response.headers)
            # If we get a set-cookie header, set it
            # TODO: better auth
            if 'set-cookie' in response.headers:
                split_cookie = response.headers["set-cookie"].split("=")
                self.cookies[split_cookie[0]] = split_cookie[1]
            
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', f'HTTP {response.status_code}')
                except:
                    error_message = f'HTTP {response.status_code}: {response.text}'
                
                return ApiResponse(success=False, error=error_message, status_code=response.status_code)
            
            try:
                json_data = response.json()
            except:
                json_data = None
            
            return ApiResponse(success=True, data=json_data, status_code=response.status_code)
            
        except requests.exceptions.RequestException as e:
            return ApiResponse(success=False, error=str(e))

    def login(self, username: str, password: str) -> ApiResponse:
        return self._make_request('POST', '/auth/login', {
            'username': username,
            'password': password
        })

    def register(self, username: str, email: str, password: str) -> ApiResponse:
        return self._make_request('POST', '/auth/register', {
            'username': username,
            'email': email,
            'password': password
        })

    def logout(self) -> ApiResponse:
        return self._make_request('POST', '/auth/logout')

    def get_current_user(self) -> ApiResponse:
        return self._make_request('GET', '/auth/me')

    def get_projects(self) -> ApiResponse:
        return self._make_request('GET', '/projects')

    def create_project(self, name: str, color: str, description: Optional[str] = None) -> ApiResponse:
        data = {
            'name': name,
            'color': color
        }
        if description is not None:
            data['description'] = description
        return self._make_request('POST', '/projects', data)

    def get_project(self, project_id: int) -> ApiResponse:
        return self._make_request('GET', f'/projects/{project_id}')

    def update_project(self, project_id: int, name: Optional[str] = None, color: Optional[str] = None, description: Optional[str] = None) -> ApiResponse:
        data = {}
        if name is not None:
            data['name'] = name
        if color is not None:
            data['color'] = color
        if description is not None:
            data['description'] = description
        return self._make_request('PUT', f'/projects/{project_id}', data)

    def get_todos(self, project_id: Optional[int] = None, status: Optional[str] = None, time_horizon: Optional[str] = None) -> ApiResponse:
        params = {}
        if project_id is not None:
            params['project_id'] = project_id
        if status is not None:
            params['status'] = status
        if time_horizon is not None:
            params['time_horizon'] = time_horizon
        return self._make_request('GET', '/todos', params=params)

    def create_todo(self, title: str, project_id: Optional[int] = None, description: Optional[str] = None, 
                   priority: str = 'medium', estimated_hours: float = 1.0, due_date: Optional[str] = None,
                   tags: Optional[list[str]] = None, context: str = 'work', time_horizon: Optional[str] = None) -> ApiResponse:
        data = {
            'title': title,
            'priority': priority,
            'estimated_hours': estimated_hours,
            'context': context
        }
        if project_id is not None:
            data['project_id'] = project_id
        if description is not None:
            data['description'] = description
        if due_date is not None:
            data['due_date'] = due_date
        if tags is not None:
            data['tags'] = tags
        if time_horizon is not None:
            data['time_horizon'] = time_horizon
        return self._make_request('POST', '/todos', data)

    def get_todo(self, todo_id: int) -> ApiResponse:
        return self._make_request('GET', f'/todos/{todo_id}')

    def update_todo(self, todo_id: int, title: Optional[str] = None, project_id: Optional[int] = None,
                   description: Optional[str] = None, priority: Optional[str] = None, 
                   estimated_hours: Optional[float] = None, status: Optional[str] = None,
                   due_date: Optional[str] = None, tags: Optional[list[str]] = None,
                   context: Optional[str] = None, time_horizon: Optional[str] = None) -> ApiResponse:
        data = {}
        if title is not None:
            data['title'] = title
        if project_id is not None:
            data['project_id'] = project_id
        if description is not None:
            data['description'] = description
        if priority is not None:
            data['priority'] = priority
        if estimated_hours is not None:
            data['estimated_hours'] = estimated_hours
        if status is not None:
            data['status'] = status
        if due_date is not None:
            data['due_date'] = due_date
        if tags is not None:
            data['tags'] = tags
        if context is not None:
            data['context'] = context
        if time_horizon is not None:
            data['time_horizon'] = time_horizon
        return self._make_request('PUT', f'/todos/{todo_id}', data)

    def update_todo_bulk(self, todo_id: int, **kwargs) -> ApiResponse:
        data = {'id': todo_id}
        data.update(kwargs)
        return self._make_request('PUT', '/todos', data)

    def complete_todo(self, todo_id: int, actual_hours: float) -> ApiResponse:
        return self._make_request('POST', f'/todos/{todo_id}/complete', {
            'actual_hours': actual_hours
        })

    def get_reports(self, start_date: str, end_date: str, status: str = 'pending', time_horizon: Optional[str] = None) -> ApiResponse:
        params = {
            'start_date': start_date,
            'end_date': end_date,
            'status': status
        }
        if time_horizon is not None:
            params['time_horizon'] = time_horizon
        return self._make_request('GET', '/reports', params=params)

    def get_oauth_clients(self) -> ApiResponse:
        return self._make_request('GET', '/oauth/clients')

    def create_oauth_client(self, name: str, redirect_uris: list[str], grant_types: Optional[list[str]] = None, scopes: Optional[list[str]] = None) -> ApiResponse:
        data = {
            'name': name,
            'redirectUris': redirect_uris
        }
        if grant_types is not None:
            data['grantTypes'] = grant_types
        if scopes is not None:
            data['scopes'] = scopes
        return self._make_request('POST', '/oauth/clients', data)

    def oauth_token_exchange(self, grant_type: str, client_id: str, client_secret: str, **kwargs) -> ApiResponse:
        data = {
            'grant_type': grant_type,
            'client_id': client_id,
            'client_secret': client_secret
        }
        data.update(kwargs)
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        response = self.session.post(f"{self.base_url}/oauth/token", data=data, headers=headers)
        
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_message = error_data.get('error_description', error_data.get('error', f'HTTP {response.status_code}'))
            except:
                error_message = f'HTTP {response.status_code}: {response.text}'
            
            return ApiResponse(success=False, error=error_message, status_code=response.status_code)
        
        try:
            json_data = response.json()
        except:
            json_data = None
        
        return ApiResponse(success=True, data=json_data, status_code=response.status_code)


def create_authenticated_client(username: str, password: str, base_url: str = "http://localhost:4321/api") -> Optional[TaskManagerAPI]:
    client = TaskManagerAPI(base_url)
    response = client.login(username, password)
    
    if response.success:
        return client
    else:
        print(f"Authentication failed: {response.error}")
        return None


if __name__ == "__main__":
    api = TaskManagerAPI()
    response = api.login(CLIENT_ID, CLIENT_SECRET)
    print(response)
    if not response.success:
        print("Login Failed...")
    else:
        projects = api.get_projects()
        print(projects)
