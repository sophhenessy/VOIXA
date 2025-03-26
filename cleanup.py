import psutil
import time

def kill_process_on_port(port):
    for proc in psutil.process_iter(['pid', 'name', 'connections']):
        try:
            connections = proc.info['connections']
            if connections:
                for conn in connections:
                    if conn.laddr.port == port:
                        print(f"Found process using port {port}: PID={proc.pid}")
                        proc.terminate()
                        proc.wait(timeout=3)
                        return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

if __name__ == "__main__":
    PORT = 5000
    print(f"Looking for process using port {PORT}...")
    if kill_process_on_port(PORT):
        print(f"Successfully killed process using port {PORT}")
        time.sleep(1)  # Give the system time to release the port
    else:
        print(f"No process found using port {PORT}")
