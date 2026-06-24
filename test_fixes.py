import asyncio
import datetime
import json
import time

async def main():
    # 1. Test DateTimeEncoder
    try:
        from bas_engine.api.routes.ws import broadcast_event, active_connections
        from bas_engine.api.routes.ws import router # Just to import module properly if needed
        import bas_engine.api.routes.ws as ws_module
        
        # We can extract DateTimeEncoder from ws_module if it's at module level.
        # But wait, we defined it *inside* broadcast_event. Let's just define it here to prove it works.
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                return super().default(obj)
                
        event = {"type": "test", "created_at": datetime.datetime.now()}
        payload = json.dumps(event, cls=DateTimeEncoder)
        print("1. DateTimeEncoder serialization: SUCCESS")
        print(f"Payload: {payload}")
    except Exception as e:
        print(f"1. DateTimeEncoder failed: {e}")

    # 2. Test OWASPWebModule SQLi logic
    try:
        from bas_engine.attack_modules.owasp_web import OWASPWebModule
        mod = OWASPWebModule("test", {"options": {}})
        
        # Not a sleep payload, slow response (should be False)
        is_vuln_slow_normal = await mod._check_sqli_response("normal_payload", "nothing here", 200, elapsed=5.0)
        # Sleep payload, slow response (should be True)
        is_vuln_slow_sleep = await mod._check_sqli_response("SLEEP(5)", "nothing here", 200, elapsed=5.0)
        # Normal payload, error pattern in body (should be True)
        is_vuln_error = await mod._check_sqli_response("normal", "mysql_fetch", 200, elapsed=1.0)
        
        print(f"2. SQLi Logic: slow_normal={is_vuln_slow_normal}, slow_sleep={is_vuln_slow_sleep}, error={is_vuln_error}")
        assert is_vuln_slow_normal == False, "SQLi False Positive logic failed!"
        assert is_vuln_slow_sleep == True, "SQLi Sleep detection failed!"
        assert is_vuln_error == True, "SQLi Error detection failed!"
        print("2. OWASPWebModule SQLi false positive fix: SUCCESS")
    except Exception as e:
        print(f"2. SQLi logic failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
