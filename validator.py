import asyncio
import json
import argparse
import os
import urllib.parse
from playwright.async_api import async_playwright
from datetime import datetime
import time
import uuid

class XSSValidator:
    def __init__(self, config, payloads):
        self.config = config
        self.payloads = payloads
        self.results = []
        self.base_url = config['target_url']
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.run_dir = os.path.join(
            self.config['validation']['artifacts_dir'],
            timestamp
        )
        os.makedirs(self.run_dir, exist_ok=True)
        self.out_file = open(os.path.join(self.run_dir, "success.json"), "w")
        self.out_file.write("[\n")
        self.log_file = open(os.path.join(self.run_dir, "log.txt"), "w")
        self.result_file = open(os.path.join(self.run_dir, "result.json"), "w")
        self.result_file.write("[\n")
        self.first_item = True
        self.result_first_item = True

    async def run(self):
        self.start_time = time.time()

        self.total_tests = sum(
            len(item.get("endpoints", ["reflected", "stored", "dom"]))
            for item in self.payloads
        )

        self.completed_tests = 0
        
        async with async_playwright() as p:
            # Tăng timeout mặc định của trình duyệt lên 60s (thay vì 30s) để tránh lỗi mạng chậm
            browser = await p.chromium.launch(headless=True, timeout=60000)
            print(f"[*] Starting Login to {self.base_url}...")
            
            login_context = await browser.new_context(ignore_https_errors=True)
            await self.perform_login(login_context)
            storage_state = await login_context.storage_state()
            await login_context.close()

            print(f"[*] Starting validation of {len(self.payloads)} payloads...")

            for item in self.payloads:
                payload_str = item['payload']
                target_endpoints = item.get('endpoints', ["reflected", "stored", "dom"])
                
                for endpoint_type in target_endpoints:
                    context = await browser.new_context(storage_state=storage_state, ignore_https_errors=True)
                    # Set timeout navigation lên 60s
                    context.set_default_timeout(1000)
                    context.set_default_navigation_timeout(3000)
                    
                    if self.config['validation']['block_external_requests']:
                        await context.route("*/", lambda route: route.abort() if self.base_url not in route.request.url else route.continue_())

                    run_id = uuid.uuid4()
                    page = await context.new_page()
                    await page.set_extra_http_headers({
                        "X-Run-Id": str(run_id),
                        "X-Payload-Id": str(item['id']),
                    })
                    
                    # Reset DB nếu là Stored XSS
                    if endpoint_type == 'stored':
                        await self.reset_dvwa_db(page)

                    evidence = await self.setup_oracle(page)

                    # print(f"Testing [{item['id']}] on [{endpoint_type}]...")
                    try:
                        if endpoint_type == 'reflected':
                            await self.validate_reflected(page, payload_str)
                        elif endpoint_type == 'stored':
                            await self.validate_stored(page, payload_str)
                        elif endpoint_type == 'dom':
                            await self.validate_dom(page, payload_str)
                        
                        try:
                            await page.wait_for_function(
                                "window.__xssExecuted === true",
                                timeout=800
                            )
                        except:
                            pass
                        
                    except Exception as e:
                        evidence['error'] = str(e)

                    result = {
                        "id": item['id'],
                        "payload": payload_str,
                        "endpoint": endpoint_type,
                        "executed": evidence['triggered'],
                        "signal_type": evidence['signal_type'],
                        "error": evidence['error']
                    }
                    
                    status = "[SUCCESS]" if evidence['triggered'] else "[FAIL]"
                    # print(f"  -> {status} Signal: {evidence['signal_type']}")

                    self.log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Run ID: {run_id} - Payload ID: {item['id']} on {endpoint_type} - {status}\n")
                    self.log_file.flush()

                    if evidence['triggered']:
                        if not self.first_item:
                            self.out_file.write(",\n")
                        else:
                            self.first_item = False

                        json.dump(result, self.out_file, indent=2)
                        self.out_file.flush()
                                   
                    if self.result_first_item:
                        self.result_first_item = False
                    else:
                        self.result_file.write(",\n")

                    json.dump(result, self.result_file, indent=2)
                    self.result_file.flush()
                    
                    self.print_progress()
                    print()

                    await context.close()

            await browser.close()

    async def perform_login(self, context):
        page = await context.new_page()
        dvwa = self.config['dvwa']
        try:
            await page.goto(f"{self.base_url}{dvwa['login_path']}")
            if await page.locator(dvwa['selectors']['login_username']).count() > 0:
                await page.fill(dvwa['selectors']['login_username'], dvwa['username'])
                await page.fill(dvwa['selectors']['login_password'], dvwa['password'])
                await page.click(dvwa['selectors']['login_submit'])
                await page.wait_for_load_state("domcontentloaded")
            
            await page.goto(f"{self.base_url}{dvwa['security_path']}")
            await page.select_option(dvwa['selectors']['security_select'], dvwa['security_level'])
            await page.click(dvwa['selectors']['security_submit'])
            await page.wait_for_load_state("domcontentloaded")
            print(f"[*] Login successful & Security set to '{dvwa['security_level']}'")
        except Exception as e:
            print(f"[!] Login Failed: {e}")

    async def reset_dvwa_db(self, page):
        """Hàm reset DB có thêm thời gian nghỉ để tránh Timeout"""
        try:
            await page.goto(f"{self.base_url}/setup.php")
            await page.click("input[name='create_db']")
            await page.wait_for_load_state("domcontentloaded")
            # --- QUAN TRỌNG: Cho server nghỉ 2 giây sau khi reset ---
            await page.wait_for_timeout(2000) 
            # --------------------------------------------------------
        except Exception:
            pass

    async def setup_oracle(self, page):
        evidence = {
            "triggered": False,
            "signal_type": None,
            "error": None
        }

        # 1️⃣ Dialog-based detection (keep this)
        async def handle_dialog(dialog):
            evidence["triggered"] = True
            evidence["signal_type"] = "dialog"
            try:
                await dialog.accept()
            except:
                pass

        page.on("dialog", handle_dialog)

        # 2️⃣ Inject execution-detection JS BEFORE page load
        await page.add_init_script("""
            (() => {
                if (window.__xssOracleInstalled) return;
                window.__xssOracleInstalled = true;

                window.__xssExecuted = false;

                const mark = () => {
                    if (!window.__xssExecuted) {
                    window.__xssExecuted = true;
                    observer.disconnect();
                    }
                };

                const observer = new MutationObserver(muts => {
                    for (const m of muts) {
                    for (const n of m.addedNodes) {
                        if (n.nodeName === 'SCRIPT') mark();
                    }
                    }
                });

                observer.observe(document.documentElement, {
                    childList: true,
                    subtree: true
                });

                window.addEventListener('error', mark, { once: true });

                ['onerror','onload','onclick'].forEach(evt => {
                    Object.defineProperty(HTMLElement.prototype, evt, {
                    set() { mark(); }
                    });
                });
            })();
        """)

        return evidence

    async def validate_reflected(self, page, payload):
        conf = self.config['endpoints']['reflected']
        await page.goto(f"{self.base_url}{conf['path']}")
        for field, selector in conf['fields'].items():
            await page.fill(selector, payload)
        
        await page.click(conf['submit'])
        await page.wait_for_load_state("domcontentloaded")

    async def validate_stored(self, page, payload):
        conf = self.config['endpoints']['stored']
        await page.goto(f"{self.base_url}{conf['path']}")
        
        await page.fill(conf['fields']['name'], "TestBot") 
        await page.fill(conf['fields']['payload'], payload)
        
        await page.click(conf['submit'])
        await page.wait_for_load_state("domcontentloaded")

        await page.goto(f"{self.base_url}{conf['render_path']}")

    async def validate_dom(self, page, payload):
        conf = self.config['endpoints']['dom']
        encoded_payload = urllib.parse.quote(payload)
        await page.goto(f"{self.base_url}{conf['path']}?{conf['param']}={encoded_payload}")
        await page.wait_for_load_state("domcontentloaded")

        try:
            await page.wait_for_function(
                "window.__xssExecuted === true",
                timeout=800
            )
        except:
            pass

    def print_progress(self):
        elapsed = time.time() - self.start_time
        self.completed_tests += 1

        avg_time = elapsed / self.completed_tests
        remaining = self.total_tests - self.completed_tests
        eta = remaining * avg_time

        percent = (self.completed_tests / self.total_tests) * 100

        print(
            f"[{self.completed_tests}/{self.total_tests}] "
            f"{percent:6.2f}% | "
            f"Elapsed: {elapsed:6.1f}s | "
            f"ETA: {eta:6.1f}s",
            end="\r",
            flush=True
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--payloads", required=True)
    args = parser.parse_args()

    with open(args.config, 'r') as f: config = json.load(f)
    with open(args.payloads, 'r') as f: payloads = json.load(f)['payloads']

    validator = XSSValidator(config, payloads)
    asyncio.run(validator.run())

if __name__ == "__main__":
    main()