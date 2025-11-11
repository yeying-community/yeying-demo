import requests
import hashlib
import hmac
import json
from datetime import datetime
from urllib.parse import urlencode

class AKSKClient:
    def __init__(self, access_key, secret_key, base_url):
        self.access_key = access_key
        self.secret_key = secret_key
        self.base_url = base_url
    
    def generate_signature(self, method, uri, query_params, headers, body, timestamp):
        """生成请求签名"""
        canonical_request_parts = [
            method.upper(),
            uri,
            '&'.join([f"{k}={v}" for k, v in sorted(query_params.items())]),
            '\n'.join([f"{k.lower()}:{v}" for k, v in sorted(headers.items()) if k.lower().startswith('x-')]),
            body if body else ""
        ]
        
        canonical_request = '\n'.join(canonical_request_parts)
        string_to_sign = f"HMAC-SHA256\n{timestamp}\n{canonical_request}"
        
        print(f"待签名字符串:\n{string_to_sign}")
        
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        print(f"生成的签名: {signature}")
        
        return signature
    
    def make_request(self, method, endpoint, params=None, data=None, headers=None):
        """发送带签名的请求"""
        url = f"{self.base_url}{endpoint}"
        
        # 准备请求参数
        query_params = params or {}
        request_headers = headers or {}
        body = json.dumps(data) if data else ""
        
        # 生成时间戳
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        print(f"\n发送请求: {method} {endpoint}")
        print(f"时间戳: {timestamp}")
        
        # 生成签名
        signature = self.generate_signature(
            method, endpoint, query_params, request_headers, body, timestamp
        )
        
        # 构建认证头
        auth_header = (
            f"HMAC-SHA256 AccessKey={self.access_key}, "
            f"Signature={signature}, Timestamp={timestamp}"
        )
        
        print(f"认证头: {auth_header}")
        
        # 设置请求头
        request_headers['Authorization'] = auth_header
        if data:
            request_headers['Content-Type'] = 'application/json'
        
        # 发送请求
        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=request_headers,
                timeout=10
            )
            return response
        except requests.exceptions.RequestException as e:
            print(f"请求失败: {e}")
            return None

def main():
    # 使用测试凭证
    client = AKSKClient(
        access_key="AKID123456789",
        secret_key="SK987654321abcdef",
        base_url="http://localhost:5001"
    )
    
    print("=== AK/SK 认证演示 ===\n")
    
    # 1. 访问公开接口（不需要认证）
    print("1. 访问公开接口:")
    try:
        response = requests.get("http://localhost:5001/public/info", timeout=10)
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}\n")
    except Exception as e:
        print(f"请求失败: {e}\n")
    
    # 2. 访问需要认证的 GET 接口
    print("2. 访问需要认证的用户列表接口:")
    response = client.make_request('GET', '/api/users')
    if response:
        print(f"状态码: {response.status_code}")
        try:
            print(f"响应: {response.json()}\n")
        except:
            print(f"响应内容: {response.text}\n")
    
    # 3. 访问需要认证的 POST 接口
    print("3. 访问需要认证的数据创建接口:")
    test_data = {"name": "测试数据", "value": 123}
    response = client.make_request('POST', '/api/data', data=test_data)
    if response:
        print(f"状态码: {response.status_code}")
        try:
            print(f"响应: {response.json()}\n")
        except:
            print(f"响应内容: {response.text}\n")
    
    # 4. 使用错误的凭证
    print("4. 使用错误的凭证:")
    bad_client = AKSKClient(
        access_key="WRONG_KEY",
        secret_key="WRONG_SECRET",
        base_url="http://localhost:5001"
    )
    response = bad_client.make_request('GET', '/api/users')
    if response:
        print(f"状态码: {response.status_code}")
        try:
            print(f"响应: {response.json()}\n")
        except:
            print(f"响应内容: {response.text}\n")
    
    # 5. 不带认证头访问受保护接口
    print("5. 不带认证头访问受保护接口:")
    try:
        response = requests.get("http://localhost:5001/api/users", timeout=10)
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.json()}")
    except Exception as e:
        print(f"请求失败: {e}")

if __name__ == '__main__':
    main()

