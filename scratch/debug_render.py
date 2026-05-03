import jinja2
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

templates = Jinja2Templates(directory="app/templates")

try:
    # Mock a request object
    scope = {"type": "http", "method": "GET", "path": "/scan", "headers": []}
    request = Request(scope)
    
    response = templates.TemplateResponse(request=request, name="scan.html", context={"active_page": "scan"})
    print("Success")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
