from flask import Flask, request, jsonify
import hashlib
import hmac
import time
import json
from datetime import datetime, timedelta

app = Flask(__name__)

# 模拟的用户数据库 (AK -> SK 映射)
USER_CREDENTIALS = {
    "AKID123456789": "SK987654321abcdef",
    "AKID111222333": "SK444555666ghijk",
}

# 存储已使用的时间戳，防止重放攻击
used_timestamps = set()

def generate_signature(method, uri, query_params, headers, body, secret_key, timestamp):
    """生成请求签名"""
    # 1. 构建规范化请求字符串
    canonical_request_parts = [
        method.upper(),
        uri,
        '&'.join([f"{k}={v}" for k, v in sorted(query_params.items())]),
        '\n'.join([f"{k.lower()}:{v}" for k, v in sorted(headers.items()) if k.lower().startswith('x-')]),
        body if body else ""
    ]
    
    canonical_request = '\n'.join(canonical_request_parts)
    
    # 2. 构建待签名字符串
    string_to_sign = f"HMAC-SHA256\n{timestamp}\n{canonical_request}"
    
    # 3. 计算签名
    signature = hmac.new(
        secret_key.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return signature

@app.route('/auth/verify', methods=['POST'])
def verify_signature():
    """验证请求签名"""
    try:
        # 获取认证头信息
        auth_header = request.headers.get('Authorization', '')
        print(f"收到认证请求，Authorization头: {auth_header}")
        
        if not auth_header.startswith('HMAC-SHA256 '):
            return jsonify({"error": "Invalid authorization header"}), 401
        
        # 解析认证头
        auth_parts = auth_header[12:].split(', ')  # 去掉 "HMAC-SHA256 "
        auth_dict = {}
        for part in auth_parts:
            if '=' in part:
                key, value = part.split('=', 1)
                auth_dict[key] = value
        
        access_key = auth_dict.get('AccessKey')
        signature = auth_dict.get('Signature')
        timestamp = auth_dict.get('Timestamp')
        
        print(f"解析结果 - AccessKey: {access_key}, Timestamp: {timestamp}")
        
        if not all([access_key, signature, timestamp]):
            return jsonify({"error": "Missing required auth parameters"}), 401
        
        # 检查 AccessKey 是否存在
        if access_key not in USER_CREDENTIALS:
            return jsonify({"error": "Invalid access key"}), 401
        
        secret_key = USER_CREDENTIALS[access_key]
        
        # 检查时间戳（防止重放攻击）
        try:
            request_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = datetime.utcnow()
            time_diff = abs((current_time - request_time.replace(tzinfo=None)).total_seconds())
            
            if time_diff > 300:  # 5分钟有效期
                return jsonify({"error": "Request expired"}), 401
            
            # 简化重放攻击检查，避免内存泄漏
            if len(used_timestamps) > 1000:
                used_timestamps.clear()
            
            if timestamp in used_timestamps:
                return jsonify({"error": "Timestamp already used"}), 401
            
            used_timestamps.add(timestamp)
        except ValueError as e:
            print(f"时间戳解析错误: {e}")
            return jsonify({"error": "Invalid timestamp format"}), 401
        
        # 获取原始请求信息
        try:
            original_request = request.get_json()
            if not original_request:
                return jsonify({"error": "Missing request data"}), 400
                
            method = original_request.get('method', '')
            uri = original_request.get('uri', '')
            query_params = original_request.get('query_params', {})
            headers = original_request.get('headers', {})
            body = original_request.get('body', '')
            
            print(f"原始请求信息 - Method: {method}, URI: {uri}")
            
        except Exception as e:
            print(f"解析请求数据错误: {e}")
            return jsonify({"error": "Invalid request data"}), 400
        
        # 计算期望的签名
        expected_signature = generate_signature(
            method, uri, query_params, headers, body, secret_key, timestamp
        )
        
        print(f"期望签名: {expected_signature}")
        print(f"实际签名: {signature}")
        
        # 验证签名
        if hmac.compare_digest(signature, expected_signature):
            print("签名验证成功")
            return jsonify({
                "status": "success",
                "message": "Authentication successful",
                "user_id": access_key
            }), 200
        else:
            print("签名验证失败")
            return jsonify({"error": "Invalid signature"}), 401
            
    except Exception as e:
        print(f"认证过程出错: {e}")
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "auth-server"}), 200

if __name__ == '__main__':
    print("认证服务器启动中...")
    print("可用的测试凭证:")
    for ak, sk in USER_CREDENTIALS.items():
        print(f"  AccessKey: {ak}")
        print(f"  SecretKey: {sk}")
    print("\n服务运行在 http://localhost:5000")
    app.run(debug=True, port=5000)

