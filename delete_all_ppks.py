#!/usr/bin/env python3
import requests
import json
import time

# Device info
device_ip = "192.168.201.34"
api_port = "4343"
username = "admin"
password = "aruba123"

def delete_all_ppks():
    print("🗑️  Delete All PPKs (starting from ppk-id-4)")
    print("=" * 50)
    
    # Login
    print("🔐 Logging in...")
    session = requests.Session()
    login_url = f"https://{device_ip}:{api_port}/v1/api/login?username={username}&password={password}"
    response = session.get(login_url, verify=False)
    
    if response.status_code != 200:
        print(f"❌ Login failed: {response.status_code}")
        return
    
    # Get tokens
    data = response.json()
    global_result = data.get('_global_result', {})
    uidaruba = global_result.get('UIDARUBA')
    csrf_token = global_result.get('X-CSRF-Token')
    
    if not uidaruba or not csrf_token:
        print("❌ Failed to get tokens")
        return
    
    print("✅ Login successful")
    
    # Delete PPKs starting from ppk-id-4
    delete_url = f"https://{device_ip}:{api_port}/v1/configuration/object/isakmp_ppk_delete?config_path=%2Fmm"
    headers = {"X-CSRF-Token": csrf_token, "Content-Type": "application/json", "Accept": "application/json"}
    
    success_count = 0
    failed_count = 0
    
    for i in range(4, 614):  # ppk-id-4 to ppk-id-613
        ppk_id = f"ppk-id-{i}"
        payload = {"peer-any": True, "ppk_id": ppk_id}
        
        print(f"🗑️  Deleting {i-3:3d}/610: {ppk_id}")
        
        try:
            response = session.post(delete_url, headers=headers, json=payload, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                global_result = data.get('_global_result', {})
                status = global_result.get('status', -1)
                
                if status == 0:
                    print(f"   ✅ SUCCESS")
                    success_count += 1
                else:
                    status_str = global_result.get('status_str', 'Unknown error')
                    print(f"   ❌ FAILED - {status_str}")
                    failed_count += 1
            else:
                print(f"   ❌ HTTP ERROR - {response.status_code}")
                failed_count += 1
                
        except Exception as e:
            print(f"   💥 EXCEPTION - {e}")
            failed_count += 1
        
        # Progress update every 50 deletions
        if i % 50 == 0:
            print(f"   📊 Progress: {i-3}/610 processed, ✅ {success_count} success, ❌ {failed_count} failed")
        
        # Small delay to avoid overwhelming the device
        time.sleep(0.05)
    
    print()
    print("🏁 Final Results:")
    print("=" * 50)
    print(f"✅ Successful deletions: {success_count}")
    print(f"❌ Failed deletions: {failed_count}")
    print(f"📊 Total processed: {success_count + failed_count}")

if __name__ == "__main__":
    delete_all_ppks()
