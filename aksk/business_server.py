from flask import Flask, request, jsonify
import requests
import hashlib
import hmac
import json
from datetime import datetime

app = Flask(__name__)

# 认证服务器地址
AUTH_SERVER_URL = "http://localhost:5000"

def verify_request_auth():
    """验证请求的认证信息"""
    try:
        # 获取认证头
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            return False, "Missing authorization header"
        
        print(f"业务服务器收到请求，Authorization: {auth_header}")
        
        # 准备发送给认证服务器的数据
        auth_data = {
            "method": request.method,
            "uri": request.path,
            "query_params": dict(request.args),
            "headers": dict(request.headers),
            "body": request.get_data(as_text=True)
        }
        
        print(f"发送给认证服务器的数据: {json.dumps(auth_data, indent=2)}")
        
        # 向认证服务器验证
        try:
            response = requests.post(
                f"{AUTH_SERVER_URL}/auth/verify",
                json=auth_data,
                headers={"Authorization": auth_header},
                timeout=10
            )
            
            print(f"认证服务器响应状态码: {response.status_code}")
            print(f"认证服务器响应内容: {response.text}")
            
            if response.status_code == 200:
                return True, response.json()
            else:
                try:
                    error_data = response.json()
                    return False, error_data.get('error', 'Authentication failed')
                except:
                    return False, f"Authentication failed with status {response.status_code}"
                    
        except requests.exceptions.Timeout:
            return False, "Authentication service timeout"
        except requests.exceptions.ConnectionError:
            return False, "Authentication service unavailable"
        except requests.exceptions.RequestException as e:
            return False, f"Authentication service error: {str(e)}"
            
    except Exception as e:
        print(f"验证认证信息时出错: {e}")
        return False, f"Authentication error: {str(e)}"

@app.route('/api/users', methods=['GET'])
def get_users():
    """获取用户列表 - 需要认证"""
    print("收到获取用户列表请求")
    is_valid, auth_result = verify_request_auth()
    
    if not is_valid:
        print(f"认证失败: {auth_result}")
        return jsonify({"error": auth_result}), 401
    
    print(f"认证成功: {auth_result}")
    
    # 模拟用户数据
    users = [
        {"id": 1, "name": "Alice", "email": "alice@example.com"},
        {"id": 2, "name": "Bob", "email": "bob@example.com"},
        {"id": 3, "name": "Charlie", "email": "charlie@example.com"}
    ]
    
    return jsonify({
        "users": users,
        "authenticated_user": auth_result.get('user_id')
    }), 200

@app.route('/api/data', methods=['POST'])
def create_data():
    """创建数据 - 需要认证"""
    print("收到创建数据请求")
    is_valid, auth_result = verify_request_auth()
    
    if not is_valid:
        print(f"认证失败: {auth_result}")
        return jsonify({"error": auth_result}), 401
    
    print(f"认证成功: {auth_result}")
    
    data = request.get_json()
    
    return jsonify({
        "message": "Data created successfully",
        "data": data,
        "created_by": auth_result.get('user_id')
    }), 201

@app.route('/public/info', methods=['GET'])
def public_info():
    """公开接口 - 不需要认证"""
    return jsonify({
        "message": "This is a public endpoint",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "business-server"}), 200

if __name__ == '__main__':
    print("业务服务器启动中...")
    print("服务运行在 http://localhost:5001")
    print("需要认证的接口:")
    print("  GET  /api/users")
    print("  POST /api/data")
    print("公开接口:")
    print("  GET  /public/info")
    app.run(debug=True, port=5001)

