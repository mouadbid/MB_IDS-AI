import socket

def check_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except Exception:
        return False

ports_to_try = [5173, 5188, 5125, 3000, 3001, 8080, 5000, 4000]
print("Checking ports...")
for p in ports_to_try:
    print(f"Port {p}: {'Available' if check_port(p) else 'Blocked/In Use'}")
