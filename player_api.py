import requests
import json
import os
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PlayerAPI:
    def __init__(self):
        self.host = "https://h72-ms-prod.netease.com"
        self.session = "aZY/GO6l/syHP1mz" 
        
        # [USER CONFIG] Cập nhật 2 thông số này từ Log/Captured Request MỚI NHẤT
        self.manual_timestamp = ""  # VD: "1755626400"
        self.manual_sign = ""       # VD: "ab82..."
        
        # HEADERS (Cố gắng giả lập giống thật nhất)
        self.headers = {
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; Pixel 6 Build/SP2A.220305.013.A3)",
            "X-Hexm-App-Id": "1",
            "X-Hexm-Client-Type": "2", # Android
            "X-Hexm-Language": "vi",
            "X-Hexm-Region": "VN",
            "X-Hexm-App-Version": "1.0.0",
            "X-Hexm-Device-Id": "1234567890123456", # Cần lấy ID thật từ log v38 nếu lỗi
            "X-Hexm-Session": self.session
        }

    def post_request(self, endpoint, data):
        url = f"{self.host}{endpoint}"
        params = {"session": self.session}
        
        # Xử lý Timestamp & Sign
        if self.manual_timestamp and self.manual_sign:
            # Dùng captured headers (Replay Attack)
            self.headers["X-Hexm-Timestamp"] = self.manual_timestamp
            self.headers["X-Hexm-Sign"] = self.manual_sign
            print(f"[*] Using MANUAL Sign/Timestamp: {self.manual_timestamp} | {self.manual_sign}")
        else:
            # Tự động tạo (Thường sẽ fail nếu không có thuật toán Sign đúng)
            ts = str(int(time.time()))
            self.headers["X-Hexm-Timestamp"] = ts
            self.headers["X-Hexm-Sign"] = "abc123" # Fake
            # print(f"[*] Auto-gen Timestamp: {ts} (Warning: Sign is FAKE)")

        try:
            print(f"[*] Post to: {endpoint}")
            # print(f"    Timestamp: {ts}")
            
            response = requests.post(url, json=data, params=params, headers=self.headers, verify=False, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, str):
                        return {"code": -1, "msg": data}
                    return data
                except:
                    return {"code": -1, "msg": response.text}
            else:
                return {"code": response.status_code, "msg": f"Http Error {response.status_code}"}
        except Exception as e:
            return {"code": -2, "msg": str(e)}

    # Thêm hàm tìm kiếm người chơi theo ID
    def find_user(self, number_id):
        endpoint = "/flk/find_people/by_number_id"
        print(f"\n[*] Searching for User ID: {number_id}")
        
        # Payload cho tìm kiếm (dựa trên log/guess)
        payload = {
            "number_id": number_id,
            "force_search": False  # Thường là false để tìm cache trước
        }
        
        # Gọi request
        return self.post_request(endpoint, payload)

    def test_lookup(self):
        # Target Number ID từ yêu cầu của User
        target_number_id = "0017698248"
        
        # BƯỚC 1: Tìm PID từ Number ID
        print(f"--- STEP 1: Find PID for Number ID {target_number_id} ---")
        find_res = self.find_user(target_number_id)
        
        pid = None
        hostnum = None
        
        if find_res.get("code") == 0:
            # Phân tích response để lấy PID
            # Cấu trúc response tìm kiếm thường trả về list user hoặc 1 user info
            # print("Find Response:", json.dumps(find_res, indent=2))
            
            # Giả định cấu trúc trả về thường thấy của NetEase
            # Có thể nằm trong data -> players -> [list] hoặc data -> user_info
            data = find_res.get("data", {})
            
            # Trường hợp 1: Trả về trực tiếp user info
            if "pid" in data:
                pid = data["pid"]
                hostnum = data.get("server_hostnum") or data.get("hostnum")
                print(f"[+] Found Direct PID: {pid} | Hostnum: {hostnum}")
                
            # Trường hợp 2: Trả về list (thường gặp)
            elif "players" in data:
                players = data["players"]
                if isinstance(players, list) and len(players) > 0:
                    first_match = players[0]
                    pid = first_match.get("pid")
                    hostnum = first_match.get("server_hostnum")
                    print(f"[+] Found in List - PID: {pid} | Hostnum: {hostnum}")
                elif isinstance(players, dict):
                    # Đôi khi là dict key=pid
                    for k, v in players.items():
                        pid = k
                        hostnum = v.get("server_hostnum")
                        print(f"[+] Found in Dict - PID: {pid} | Hostnum: {hostnum}")
                        break
            
        else:
            print(f"[-] Find Failed. Full Response: {json.dumps(find_res, indent=2, ensure_ascii=False)}")
            # Nếu tìm kiếm thất bại, có thể thử hardcode nếu user biết PID
            # pid = "Z37zk9TcC2oMmXkG" 
            # hostnum = "10020"
            pass

        if not pid or not hostnum:
            print("[!] Cannot proceed to Step 2 without PID/Hostnum.")
            return

        # BƯỚC 2: Get Profile Chi Tiết
        print(f"\n--- STEP 2: Get Detailed Profile (PID: {pid}) ---")
        
        payload = {
            "hostnum2pids": {str(hostnum): [pid]},
            "fields": ["base", "head", "name_card", "social"] # Thêm fields nếu cần
        }
        
        res = self.post_request("/flk/redis_player/get_players_info", payload)
        
        if res.get("code") == 0:
            print("[SUCCESS] Data Retrieved!")
            players = res.get("data", {}).get("players", {})
            target = players.get(pid, {})
            base = target.get("base", {})
            
            if base:
                print("\n=== EXPECTED DATA FORMAT ===")
                # In ra dạng JSON như user mong đợi
                print(json.dumps(base, indent=2, ensure_ascii=False))
            else:
                print("[!] Player found but 'base' field is missing.")
                print(json.dumps(res, indent=2, ensure_ascii=False))
                
        elif res.get("msg") == "interface error.":
             print("[FAIL] Session REJECTED (Interface Error).")
             print("Reason: Timestamp too old OR Signature Invalid.")
             print("Solution: Run Injector v38 to capture REAL Sign/Timestamp.")
        else:
             print(f"[FAIL] API Error: {res.get('msg')}")

if __name__ == "__main__":
    api = PlayerAPI()
    api.test_lookup()
