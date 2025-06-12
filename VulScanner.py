# Standard Library
import datetime
import json
import os
import re
import requests
import socket
import sys
import time
import webbrowser
import winreg
from typing import Dict, List, Tuple, Any

# Third-Party

from colorama import Fore, Style, init
from openai import OpenAI
from tabulate import tabulate
from tqdm import tqdm




# Configuration
VULNERS_API_URL = "https://vulners.com/api/v4/audit/software"
VULNERS_API_KEY = "" # Add your own API key here
REQUEST_DELAY = 3  

# -------------------------
# Step 1: Show Disclamier |
# -------------------------
def show_disclaimer():
    print(Fore.YELLOW + "="*80)
    print(Fore.YELLOW + "#" + Style.RESET_ALL + " "*30 + "Murdoch University" + " "*30 + Fore.YELLOW + "#")   
    print(Fore.YELLOW + "#" + Style.RESET_ALL + " "*34 + "DISCLAIMER" + " "*34 + Fore.YELLOW + "#")
    print(Fore.YELLOW + "="*80)
    print("\nThis tool is developed as part of a student research project by "+ Fore.YELLOW + "Tashi Dorji" + Style.RESET_ALL)
    print("under the supervision of "+ Fore.YELLOW + "Dr. Sebastian Zander " + Style.RESET_ALL + "(Senior Lecturer) Murdoch University.\n")
    print("By continuing, you acknowledge the following:")
    print("- This tool scans installed programs to identify known vulnerabilities.")
    print("- It does not modify or alter your system in any way.")
    print("- It is intended for educational and research purposes only.")
    print("- No personal data is collected or stored.")
    print("- The tool may make mistakes. Please use with discretion.\n")
    print("Do you agree to continue and use this tool?")


    user_input = input("Type 'Yes' to continue or anything else to exit: ").strip().lower()

    if user_input != "yes":
        print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Exiting the program now.")
        time.sleep(2)
        sys.exit(0)
    else:
        print(f"{Fore.GREEN}{Style.BRIGHT}[OK] {Style.RESET_ALL} Checking your internet connection now.")

    if not check_internet_connection():
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {Style.RESET_ALL} Oops! It looks like you're not connected to the internet.")
        print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Please connect to the internet and try again.")
        time.sleep(3)
        sys.exit(1)
    else:
        print(f"{Fore.GREEN}{Style.BRIGHT}[SUCCESS] {Style.RESET_ALL} Internet connection confirmed.")
        print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Proceeding with the scan...")
        time.sleep(3)
        
    

# ----------------------------------------
# Step 2: Check for Internet Connection  |
# ----------------------------------------
def check_internet_connection() -> bool:
    """Check for active internet connection"""
    try:
        # Try to connect to Google DNS server
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False


# --------------------------------------
# Step 3: Retrieve Installed Programs  |
# --------------------------------------
def get_installed_programs() -> List[Tuple[str, str]]:
    """
    Retrieves installed programs from Windows Registry.
    Returns list of tuples (normalized_program_name, version),
    excluding Microsoft/Windows native apps and cleaning architecture/version info from names.
    """
    programs = []
    seen = set()  # Track unique (name, version) pairs
    registry_locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    # Remove 64-bit, 64bit, x64, etc.
    arch_pattern = re.compile(r'\s*(\(?\b(64[\s-]?bit|32[\s-]?bit|x64|x86|86bit)\b\)?)', re.IGNORECASE)

    # Remove version-like substrings at the end or inside name
    version_in_name_pattern = re.compile(r'\s*(v?(\d+\.)*\d+([a-zA-Z]*)?)$', re.IGNORECASE)
    
    # Remove trailing zero from version
    trailing_dot_zero_pattern = re.compile(r'(\.0)+$')

    for hive, subkey in registry_locations:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] or "N/A"

                                # Skip Microsoft or Windows native programs
                                if name.lower().startswith(("microsoft", "windows", "msvc", "visual c++", ".net", "office")):
                                    continue

                                # Remove architecture info
                                name = arch_pattern.sub('', name).strip()

                                # Remove version number from the name
                                name = version_in_name_pattern.sub('', name).strip()

                                # Remove trailing .0 from version string
                                cleaned_version = trailing_dot_zero_pattern.sub('', str(version)).strip()
                                
                                # Deduplicate
                                if (name, cleaned_version) not in seen:
                                    seen.add((name, cleaned_version))
                                    programs.append((name, cleaned_version))
                                
                            except OSError:
                                continue
                    except OSError:
                        continue
        except OSError:
            continue

    return sorted(programs, key=lambda x: x[0].lower())

    
# -------------------------------------
# Step 4: Display Installed Programs  |
# -------------------------------------
def display_installed_programs(programs: List[Tuple[str, str]]) -> None:
    """
    Displays the programs in a formatted table.
    """
    if not programs:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[WARNING] {Style.RESET_ALL} No programs found.")
        time.sleep(2)
        return
    
    headers = ["#", "Program Name", "Version"]
    table_data = [[i+1, name[:60], version] 
                 for i, (name, version) in enumerate(programs)]
    
    print(f"\n{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Installed Programs List")
    print(tabulate(table_data, headers=headers, tablefmt="grid", maxcolwidths=[5, 60, 20]))
    print(f"\n{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Total programs found: {len(programs)}")
    time.sleep(5)


# -------------------------------------
# Step 5: Search For Vulnerabilities  |
# -------------------------------------
def search_for_vulnerabilities(programs: List[Tuple[str, str]]) -> None:
    print(f"\n{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Starting search for known vulnerabilities using {Fore.YELLOW}{Style.BRIGHT} Vulners.com API {Style.RESET_ALL}")

    vulnerable_programs = []
    max_retries = 3
    
    for i, (software, version) in enumerate(programs, 1):
        print(f"\n{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} {i}. Searching vulnerabilities for {Fore.YELLOW}{Style.BRIGHT} {software} {version} {Style.RESET_ALL}")

        payload = {
            "software": [
                {
                    "product": software,
                    "version": version
                }
            ],
            "apiKey": VULNERS_API_KEY,
            "fields": ["title", "short_description", "ai_score", "href", "published"]
        }

        for attempt in range(max_retries):
            try:
                response = requests.post(
                    VULNERS_API_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=20
                )
                response.raise_for_status()
                results = response.json()

                entries = results.get("result", [])

                if not entries:
                    print(f"{Fore.GREEN}{Style.BRIGHT}[GOOD] {Style.RESET_ALL} No known vulnerabilities found for {software} {version}")
                    break

                # Track the highest severity vulnerability for this software
                highest_severity_vuln = None
                highest_cvss = -1

                for entry in entries:
                    vulns = entry.get("vulnerabilities", [])
                    if vulns:
                        print(f"{Fore.RED}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Vulnerabilities found for {Fore.RED}{Style.BRIGHT} {software} {version}{Style.RESET_ALL}:")
                        
                        # First, display all vulnerabilities for user information
                        for vuln in vulns:
                            title = vuln.get("title")
                            description = vuln.get("short_description")
                            ai_score = vuln.get("ai_score")
                            href = vuln.get("href")
                            published = vuln.get("published")
                            
                            # Extract just the CVSS value if it's a dictionary
                            cvss_score = ai_score.get('value') if isinstance(ai_score, dict) else 0
                           
                            print(f"{Fore.RED}{Style.BRIGHT} - Title: {Style.RESET_ALL} {title}")
                            print(f"{Fore.RED}{Style.BRIGHT} - Description: {Style.RESET_ALL} {description}")
                            print(f"{Fore.RED}{Style.BRIGHT} - Risk Level: {Style.RESET_ALL} {cvss_score}")
                            print(f"{Fore.RED}{Style.BRIGHT} - Source: {Style.RESET_ALL} {href}\n")
                            
                            # Check if this is the highest severity vulnerability so far
                            if cvss_score > highest_cvss:
                                highest_cvss = cvss_score
                                highest_severity_vuln = {
                                    "software": software,
                                    "version": version,
                                    "title": title,
                                    "short_description": description,
                                    "cvss_score": cvss_score,
                                    "href": href,
                                    "published": published
                                }
                        
                        # Add only the highest severity vulnerability to our results
                        if highest_severity_vuln:
                            print(f"{Fore.YELLOW}{Style.BRIGHT}[NOTE] {Style.RESET_ALL} Adding highest severity vulnerability (CVSS: {highest_cvss}) to report.\n")
                            vulnerable_programs.append(highest_severity_vuln)
                    else:
                        print(f"{Fore.GREEN}{Style.BRIGHT}[GOOD] {Style.RESET_ALL} No known vulnerabilities found for {software} {version}")

                break  # Success — exit retry loop

            except requests.RequestException as e:
                print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Attempt {attempt + 1} failed for {software} {version}: {e}")
                if attempt < max_retries - 1:
                    print("Retrying...")
                    time.sleep(REQUEST_DELAY)
                else:
                    print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Failed after multiple attempts.")

        time.sleep(REQUEST_DELAY)

    return vulnerable_programs


# ------------------------------------------------
# Step 6: Summarize Vulnerabilities with OpenAI  |
# ------------------------------------------------
def summarize_vulnerabilities_with_openai(vulnerabilities: List[Dict[str, str]]) -> List[Dict[str, str]]:
    client = OpenAI(api_key="") # Add your own API key here

    cache_file = "vuln_summary_cache.json"
    
    # Load cache if exists
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            cache = json.load(f)
    else:
        cache = {}

    prompt_template = """
As a cybersecurity expert, your task is to translate complex vulnerabilities into clear, relatable explanations that anyone—regardless of technical knowledge—can understand. 
Your goal is to eliminate jargon, describe how the attack works using realistic examples, and give practical advice without exaggeration or fluff. 
Convert the technical vulnerability below into an easy-to-follow explanation using this structure:
# WHAT'S WRONG?
- Start by briefly explaining what the program does and how people typically use it.
- In 2 to 3 sentences, describe how the vulnerability can be triggered through normal user behavior.
- Focus on realistic steps a user might take (e.g., opening an email attachment, clicking a file, visiting a site), and how that leads to the attack.
- Your goal is to help users visualize the actual sequence of actions that lead to the problem, without using technical terms.

# BAD THINGS THAT COULD HAPPEN
- List up to 5 short bullet points.
- Each point should:
    - Start with the realistic consequence first.
    - Describe how the consequence arises based on how the vulnerability works.
- Adjust tone based on severity:
    - For critical issues (e.g. code execution): Use calm urgency (“Malicious files could take control of your device.”).
    - For low/medium issues (e.g. info leak or DoS): Be honest (“An attacker might cause the program to crash.”).
- If the vulnerability has limited impact, say so clearly (“This only affects you if you open files from untrusted sources.”).


# HOW TO FIX IT
- Provide clear, actionable steps assuming the user is already using the vulnerable version in numbered format.
- Assume the vulnerable version is already installed — no need to “check” again.
- Skip any steps that tell them to "check if they are running the vulnerable version" — it is already known.
- Include only necessary steps. Common actions specific to the program such as:
    - Update to a safe version.
    - Uninstall or disable the vulnerable software (if no fix is available).
    - Temporarily avoid risky behavior (e.g., do not open unknown files).
    - Be honest if no fix is available yet, and suggest practical safety measures.
- Be clear if the fix requires a restart, internet connection, or causes downtime.
- Do not include empty closing lines like “By following these steps…”.

TECHNICAL DETAILS:
- Software and version: {software}.
- CVE ID or Title: {title}.
- Vulnerability Description: {description}.

FORMAT RULES:
- No markdown formatting—plain text only.
- Separate sections with blank lines for readability.
- Keep the response concise—maximum of 500 words."""

    summarized = []

    for vuln in tqdm(vulnerabilities, desc="Summarizing vulnerabilities using ChatGPT"):
        cache_key = f"{vuln['software']}|{vuln['version']}|{vuln['title']}"

        if cache_key in cache:
            vuln['summary'] = cache[cache_key]
            summarized.append(vuln)
            continue

        full_prompt = prompt_template.format(
            software=f"{vuln['software']} {vuln['version']}",
            title=vuln['title'],
            description=vuln['short_description']
        )

        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.3,
                messages=[
                    {"role": "user", "content": full_prompt}
                ]
            )

            summary = response.choices[0].message.content.strip()
            vuln['summary'] = summary
            summarized.append(vuln)

            # Save to cache
            cache[cache_key] = summary
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)

            time.sleep(3)  # Wait before next request

        except Exception as e:
            print(f"{Fore.YELLOW}{Style.BRIGHT}[WARNING] {Style.RESET_ALL} Failed to summarize: {vuln['software']} {vuln['version']} - {e}")

    return summarized
 


# ------------------------------------------
# Step 7: Generate Vulnerabilities Report  |
# ------------------------------------------
def generate_report(vulnerabilities: List[Dict[str, str]]):
    def parse_summary(summary: str):
        sections = {"what": "", "impact": "", "fix": ""}
        
        # Normalize and split the summary into sections
        lines = summary.splitlines()
        current_section = None
        buffer = []

        for line in lines:
            upper = line.strip().upper()
            if "WHAT'S WRONG?" in upper:
                if current_section:
                    sections[current_section] = "\n".join(buffer).strip()
                    buffer = []
                current_section = "what"
            elif "BAD THINGS THAT COULD HAPPEN" in upper:
                if current_section:
                    sections[current_section] = "\n".join(buffer).strip()
                    buffer = []
                current_section = "impact"
            elif "HOW TO FIX IT" in upper:
                if current_section:
                    sections[current_section] = "\n".join(buffer).strip()
                    buffer = []
                current_section = "fix"
            else:
                buffer.append(line)

        if current_section and buffer:
            sections[current_section] = "\n".join(buffer).strip()

        return sections

    # Function to get severity category and color based on CVSS score
    def get_severity_info(cvss_score):
        if cvss_score >= 9.0:
            return "Critical", "red-600", "bg-red-100"
        elif cvss_score >= 7.0:
            return "High", "orange-600", "bg-orange-100"
        elif cvss_score >= 4.0:
            return "Medium", "yellow-600", "bg-yellow-100"
        else:
            return "Low", "blue-600", "bg-blue-100"

    def generate_security_insights(severity_counts):
        """Generate security insights based on vulnerability counts"""
        critical_count = severity_counts["Critical"]
        high_count = severity_counts["High"] 
        medium_count = severity_counts["Medium"]
        low_count = severity_counts["Low"]
        
        total_count = sum(severity_counts.values())
        
        if total_count == 0:
            return "Great news! No vulnerabilities were found in your system."
        
        # Calculate percentages
        critical_high_count = critical_count + high_count
        critical_high_percentage = round((critical_high_count / total_count) * 100) if total_count > 0 else 0
        
        # Build the main message
        vulnerability_word = "vulnerability" if total_count == 1 else "vulnerabilities"
        insight = f"Your system has {total_count} {vulnerability_word}"
        
        # Add severity distribution information
        if critical_high_count > 0:
            insight += f", with {critical_high_percentage}% falling in the Critical to High range"
        
        # Determine urgency level and recommendations
        if critical_count > 0:
            if critical_high_percentage >= 80:
                insight += ". This indicates a need for immediate security attention"
            elif critical_high_percentage >= 50:
                insight += ". This requires urgent security attention"
            else:
                insight += ". This needs prompt security attention"
                
            # Add specific recommendations
            insight += ". We recommend addressing"
            
            recommendations = []
            if critical_count > 0:
                critical_word = "vulnerability" if critical_count == 1 else "vulnerabilities"
                recommendations.append(f"the {critical_count} Critical {critical_word} first")
            
            if high_count > 0:
                high_word = "issue" if high_count == 1 else "issues"
                recommendations.append(f"the {high_count} High severity {high_word}")
            
            if medium_count > 0:
                medium_word = "vulnerability" if medium_count == 1 else "vulnerabilities"
                recommendations.append(f"the {medium_count} Medium severity {medium_word}")
            
            if low_count > 0:
                low_word = "issue" if low_count == 1 else "issues"
                recommendations.append(f"the {low_count} Low severity {low_word}")
            
            # Join recommendations appropriately
            if len(recommendations) == 1:
                insight += f" {recommendations[0]}"
            elif len(recommendations) == 2:
                insight += f" {recommendations[0]}, followed by {recommendations[1]}"
            else:
                insight += f" {', '.join(recommendations[:-1])}, and finally {recommendations[-1]}"
                
        elif high_count > 0:
            insight += ". While not critical, these High severity issues should be addressed promptly"
            insight += f". Focus on resolving the {high_count} High severity vulnerabilities"
            
            if medium_count > 0 or low_count > 0:
                insight += ", then address the remaining lower severity issues"
                
        elif medium_count > 0:
            insight += ". These Medium severity vulnerabilities should be addressed in your next maintenance cycle"
            
            if low_count > 0:
                insight += f", along with the {low_count} Low severity issues"
                
        else:  # Only low severity
            insight += ". These Low severity issues can be addressed during routine maintenance"
        
        insight += "."
        
        return insight

    def get_severity_colors(severity_name):
        """Get color classes based on severity"""
        color_map = {
            "Critical": {
                'bg': 'bg-red-50', 'border': 'border-red-100', 'text': 'text-red-800',
                'icon': 'text-red-600', 'badge_bg': 'bg-red-100', 'badge_text': 'text-red-800'
            },
            "High": {
                'bg': 'bg-orange-50', 'border': 'border-orange-100', 'text': 'text-orange-800',
                'icon': 'text-orange-600', 'badge_bg': 'bg-orange-100', 'badge_text': 'text-orange-800'
            },
            "Medium": {
                'bg': 'bg-yellow-50', 'border': 'border-yellow-100', 'text': 'text-yellow-800',
                'icon': 'text-yellow-600', 'badge_bg': 'bg-yellow-100', 'badge_text': 'text-yellow-800'
            },
            "Low": {
                'bg': 'bg-blue-50', 'border': 'border-blue-100', 'text': 'text-blue-800',
                'icon': 'text-blue-600', 'badge_bg': 'bg-blue-100', 'badge_text': 'text-blue-800'
            }
        }
        return color_map.get(severity_name, color_map["Low"])

    # Sort vulnerabilities by CVSS score in descending order
    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: float(x.get('cvss_score', 0)), reverse=True)
    
    # FIXED: Group vulnerabilities by severity - ensure consistent severity mapping
    severity_groups = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": []
    }
    
    for vuln in sorted_vulnerabilities:
        cvss_score = float(vuln.get('cvss_score', 0))
        severity, _, _ = get_severity_info(cvss_score)
        severity_groups[severity].append(vuln)

    # Calculate counts and percentages
    severity_counts = {level: len(severity_groups[level]) for level in ["Critical", "High", "Medium", "Low"]}
    total_vulnerabilities = sum(severity_counts.values())
    
    severity_percentages = {
        level: (severity_counts[level] / total_vulnerabilities) * 100 if total_vulnerabilities > 0 else 0
        for level in ["Critical", "High", "Medium", "Low"]
    }
    
    # Generate the security insights
    security_insight = generate_security_insights(severity_counts)
    
    # Build the dashboard
    dashboard = f"""
    <!-- The vulnerability statistics cards -->
    <div class="mb-8" x-data="{{ chartData: [{severity_counts['Critical']}, {severity_counts['High']}, {severity_counts['Medium']}, {severity_counts['Low']}] }}">
        <!-- Section Header -->
        <div class="flex items-center mb-6">
            <div class="bg-gradient-to-r from-blue-600 to-indigo-600 p-3 rounded-xl shadow-md mr-4">
                <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                    ></path>
                </svg>
            </div>
            <div>
                <h2 class="text-2xl font-bold text-gray-800">Vulnerability Summary</h2>
                <p class="text-gray-500 text-sm mt-1">Distribution of detected vulnerabilities by severity level</p>
            </div>
        </div>

        <!-- Statistics Cards Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            
            <!-- Critical Card -->
            <div class="stat-card group relative overflow-hidden bg-white rounded-xl shadow-md border border-red-100 transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
                <!-- Top Accent Bar -->
                <div class="h-1.5 w-full bg-gradient-to-r from-red-500 to-red-600"></div>

                <!-- Card Content -->
                <div class="p-5">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center">
                            <div class="bg-red-100 p-2 rounded-lg mr-3">
                                <svg class="w-6 h-6 text-red-600 group-hover:animate-pulse" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="font-bold text-gray-700">Critical</h3>
                                <p class="text-xs text-gray-500">CVSS: 9.0 - 10.0</p>
                            </div>
                        </div>
                        <div class="text-4xl font-bold text-red-600">{severity_counts["Critical"]}</div>
                    </div>

                    <!-- Progress Bar -->
                    <div class="mt-2">
                        <div class="flex items-center justify-between text-xs mb-1">
                            <span class="text-gray-500">Percentage of total</span>
                            <span class="font-medium text-red-600"> {severity_percentages['Critical']}%</span>
                        </div>
                        <div class="w-full bg-gray-100 rounded-full h-2">
                            <div class="bg-gradient-to-r from-red-500 to-red-600 h-2 rounded-full" style="width: {severity_percentages['Critical']}%"></div>
                        </div>
                    </div>

                    <!-- Recommendation -->
                    <div class="mt-4 pt-3 border-t border-gray-100 text-xs text-gray-600">
                        <div class="flex items-center">
                            <svg class="w-4 h-4 text-red-500 mr-1 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <span>Immediate remediation strongly recommended</span>
                        </div>
                    </div>
                </div>

                <!-- Background Decoration -->
                <div class="absolute -right-6 -bottom-6 w-24 h-24 rounded-full bg-red-100 opacity-50"></div>
            </div>

            <!-- High Card -->
            <div class="stat-card group relative overflow-hidden bg-white rounded-xl shadow-md border border-orange-100 transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
                <!-- Top Accent Bar -->
                <div class="h-1.5 w-full bg-gradient-to-r from-orange-500 to-orange-600"></div>

                <!-- Card Content -->
                <div class="p-5">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center">
                            <div class="bg-orange-100 p-2 rounded-lg mr-3">
                                <svg class="w-6 h-6 text-orange-600" fill="currentColor" viewBox="0 0 20 20">
                                    <path
                                        fill-rule="evenodd"
                                        d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                                        clip-rule="evenodd"
                                    ></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="font-bold text-gray-700">High</h3>
                                <p class="text-xs text-gray-500">CVSS: 7.0 - 8.9</p>
                            </div>
                        </div>
                        <div class="text-4xl font-bold text-orange-600">{severity_counts["High"]}</div>
                    </div>

                    <!-- Progress Bar -->
                    <div class="mt-2">
                        <div class="flex items-center justify-between text-xs mb-1">
                            <span class="text-gray-500">Percentage of total</span>
                            <span class="font-medium text-orange-600"> {severity_percentages['High']}%</span>
                        </div>
                        <div class="w-full bg-gray-100 rounded-full h-2">
                            <div class="bg-gradient-to-r from-orange-500 to-orange-600 h-2 rounded-full" style="width: {severity_percentages['High']}%"></div>
                        </div>
                    </div>

                    <!-- Recommendation -->
                    <div class="mt-4 pt-3 border-t border-gray-100 text-xs text-gray-600">
                        <div class="flex items-center">
                            <svg class="w-4 h-4 text-orange-500 mr-1 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <span>Prioritize remediation within 7-14 days</span>
                        </div>
                    </div>
                </div>

                <!-- Background Decoration -->
                <div class="absolute -right-6 -bottom-6 w-24 h-24 rounded-full bg-orange-100 opacity-50"></div>
            </div>

            <!-- Medium Card -->
            <div class="stat-card group relative overflow-hidden bg-white rounded-xl shadow-md border border-yellow-100 transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
                <!-- Top Accent Bar -->
                <div class="h-1.5 w-full bg-gradient-to-r from-yellow-500 to-yellow-600"></div>

                <!-- Card Content -->
                <div class="p-5">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center">
                            <div class="bg-yellow-100 p-2 rounded-lg mr-3">
                                <svg class="w-6 h-6 text-yellow-600" fill="currentColor" viewBox="0 0 20 20">
                                    <path
                                        fill-rule="evenodd"
                                        d="M10 18a8 8 0 100-16 8 8 0 000 16zM7 9a1 1 0 100-2 1 1 0 000 2zm7-1a1 1 0 11-2 0 1 1 0 012 0zm-7.536 5.879a1 1 0 001.415 0 3 3 0 014.242 0 1 1 0 001.415-1.415 5 5 0 00-7.072 0 1 1 0 000 1.415z"
                                        clip-rule="evenodd"
                                    ></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="font-bold text-gray-700">Medium</h3>
                                <p class="text-xs text-gray-500">CVSS: 4.0 - 6.9</p>
                            </div>
                        </div>
                        <div class="text-4xl font-bold text-yellow-600">{severity_counts["Medium"]}</div>
                    </div>

                    <!-- Progress Bar -->
                    <div class="mt-2">
                        <div class="flex items-center justify-between text-xs mb-1">
                            <span class="text-gray-500">Percentage of total</span>
                            <span class="font-medium text-yellow-600"> {severity_percentages['Medium']}%</span>
                        </div>
                        <div class="w-full bg-gray-100 rounded-full h-2">
                            <div class="bg-gradient-to-r from-yellow-500 to-yellow-600 h-2 rounded-full" style="width: {severity_percentages['Medium']}%"></div>
                        </div>
                    </div>

                    <!-- Recommendation -->
                    <div class="mt-4 pt-3 border-t border-gray-100 text-xs text-gray-600">
                        <div class="flex items-center">
                            <svg class="w-4 h-4 text-yellow-500 mr-1 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <span>Plan remediation within 30 days</span>
                        </div>
                    </div>
                </div>

                <!-- Background Decoration -->
                <div class="absolute -right-6 -bottom-6 w-24 h-24 rounded-full bg-yellow-100 opacity-50"></div>
            </div>

            <!-- Low Card -->
            <div class="stat-card group relative overflow-hidden bg-white rounded-xl shadow-md border border-blue-100 transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
                <!-- Top Accent Bar -->
                <div class="h-1.5 w-full bg-gradient-to-r from-blue-500 to-blue-600"></div>

                <!-- Card Content -->
                <div class="p-5">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center">
                            <div class="bg-blue-100 p-2 rounded-lg mr-3">
                                <svg class="w-6 h-6 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                                </svg>
                            </div>
                            <div>
                                <h3 class="font-bold text-gray-700">Low</h3>
                                <p class="text-xs text-gray-500">CVSS: 0.1 - 3.9</p>
                            </div>
                        </div>
                        <div class="text-4xl font-bold text-blue-600">{severity_counts["Low"]}</div>
                    </div>

                    <!-- Progress Bar -->
                    <div class="mt-2">
                        <div class="flex items-center justify-between text-xs mb-1">
                            <span class="text-gray-500">Percentage of total</span>
                            <span class="font-medium text-blue-600"> {severity_percentages['Low']}%</span>
                        </div>
                        <div class="w-full bg-gray-100 rounded-full h-2">
                            <div class="bg-gradient-to-r from-blue-500 to-blue-600 h-2 rounded-full" style="width: {severity_percentages['Low']}%"></div>
                        </div>
                    </div>

                    <!-- Recommendation -->
                    <div class="mt-4 pt-3 border-t border-gray-100 text-xs text-gray-600">
                        <div class="flex items-center">
                            <svg class="w-4 h-4 text-blue-500 mr-1 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            <span>Address during regular maintenance cycles</span>
                        </div>
                    </div>
                </div>
                
                <!-- Background Decoration -->
                <div class="absolute -right-6 -bottom-6 w-24 h-24 rounded-full bg-blue-100 opacity-50"></div>
            </div>
        </div>

        <!-- Summary Insights -->
        <div class="mt-6 bg-white p-4 rounded-xl shadow-md border border-gray-100">
            <div class="flex items-start">
                <svg class="w-5 h-5 text-indigo-600 mt-0.5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                </svg>
                <div>
                    <h4 class="font-medium text-gray-800">Security Insight</h4>
                    <p class="text-sm text-gray-600 mt-1">
                        {security_insight}
                    </p>
                </div>
            </div>
        </div>
    </div>
    """
    # Dashboard ends here
    
               
    # Vulnerability blocks start
    vul_block = ''
    vul_block += '''
    <!-- Vulnerability Sections Container -->
    <div class="space-y-6 mb-8">
        <!-- Section Title -->
        <div class="flex items-center mb-4">
            <div class="bg-gradient-to-r from-indigo-600 to-blue-600 p-3 rounded-xl shadow-md mr-4">
                <svg class="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
            </div>
            <div>
                <h2 class="text-2xl font-bold text-gray-800">Detected Vulnerabilities</h2>
                <p class="text-gray-500 text-sm mt-1">Security issues requiring attention</p>
            </div>
        </div>
    '''
    
    # Configuration for each severity level
    severity_section_configs = {
        "Critical": {
            "gradient": "bg-gradient-to-r from-red-500 to-red-600",
            "border": "border-red-100",
            "icon": '<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>',
            "description": "CVSS Score: 9.0-10.0 | Immediate action required",
            "text_color": "text-red-100"
        },
        "High": {
            "gradient": "bg-gradient-to-r from-orange-500 to-orange-600", 
            "border": "border-orange-100",
            "icon": '<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>',
            "description": "CVSS Score: 7.0-8.9 | Prioritize within 7-14 days",
            "text_color": "text-orange-100"
        },
        "Medium": {
            "gradient": "bg-gradient-to-r from-yellow-500 to-yellow-600",
            "border": "border-yellow-100", 
            "icon": '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM7 9a1 1 0 100-2 1 1 0 000 2zm7-1a1 1 0 11-2 0 1 1 0 012 0zm-7.536 5.879a1 1 0 001.415 0 3 3 0 014.242 0 1 1 0 001.415-1.415 5 5 0 00-7.072 0 1 1 0 000 1.415z" clip-rule="evenodd"></path>',
            "description": "CVSS Score: 4.0-6.9 | Plan remediation within 30 days",
            "text_color": "text-yellow-100"
        },
        "Low": {
            "gradient": "bg-gradient-to-r from-blue-500 to-blue-600",
            "border": "border-blue-100",
            "icon": '<path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>',
            "description": "CVSS Score: 0.1-3.9 | Address during regular maintenance", 
            "text_color": "text-blue-100"
        }
    }
    
    # Generate sections for each severity level
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(severity, 0)
        config = severity_section_configs[severity]
        vulns = severity_groups.get(severity, [])
        
        # Determine if section should be open by default (Critical = open, others = closed)
        default_open = "true" if severity == "Critical" else "false"
        
        # Start severity section
        vul_block += f'''
        <!-- {severity} Vulnerabilities Section -->
        <div class="bg-white rounded-xl shadow-md overflow-hidden border {config["border"]}" x-data="{{ open: {default_open} }}">
            <!-- Section Header -->
            <div class="p-4 {config["gradient"]} text-white cursor-pointer" @click="open = !open">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <div class="bg-white/10 p-2 rounded-lg">
                            <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                                {config["icon"]}
                            </svg>
                        </div>
                        <div>
                            <h2 class="text-xl font-bold">{severity} Severity ({count})</h2>
                            <p class="text-sm {config["text_color"]}">{config["description"]}</p>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <span class="mr-2 text-sm font-medium text-white" x-text="open ? 'Hide Details' : 'Show Details'"></span>
                        <svg :class="open ? 'transform rotate-180' : ''" class="w-5 h-5 transition-transform duration-200" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                </div>
            </div>

            <!-- Vulnerability Details -->
            <div x-show="open" 
                x-transition:enter="transition ease-out duration-300"
                x-transition:enter-start="opacity-0 transform -translate-y-4"
                x-transition:enter-end="opacity-100 transform translate-y-0"
                x-transition:leave="transition ease-in duration-200"
                x-transition:leave-start="opacity-100 transform translate-y-0"
                x-transition:leave-end="opacity-0 transform -translate-y-4">
        '''
                
        # FIXED: Check both count and actual vulns length for consistency
        if count == 0 or len(vulns) == 0:
            vul_block += f'''
                <div class="p-6">
                    <div class="flex items-center justify-center py-4 text-gray-500">
                        <svg class="w-8 h-8 text-gray-300 mr-3" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                        <p>No {severity.lower()} severity vulnerabilities detected</p>
                    </div>
                </div>
            '''
        else:
            # Start container for vulnerability details
            vul_block += '''
                <div class="divide-y divide-gray-100">
            '''
            
            # Process each vulnerability
            for vuln in vulns:
                # Parse the vulnerability summary
                parts = parse_summary(vuln.get('summary', ''))
                
                # Get severity info and colors
                cvss_score = float(vuln.get('cvss_score', 0))
                severity_name, _, _ = get_severity_info(cvss_score)
                color_classes = get_severity_colors(severity_name)
                
                vul_block += f'''
                    <div class="p-6">
                        <!-- Vulnerability Header -->
                        <div class="flex flex-col md:flex-row md:items-start justify-between mb-5">
                            <div class="flex-1">
                                <div class="flex items-center space-x-2">
                                    <div class="{color_classes.get('badge_bg', 'bg-gray-100')} p-1.5 rounded-full">
                                        <svg class="w-5 h-5 {color_classes.get('icon', 'text-gray-600')}" fill="currentColor" viewBox="0 0 20 20">
                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                                        </svg>
                                    </div>
                                    <h3 class="text-xl font-bold text-gray-800">{vuln.get('software', 'Unknown Software')} {vuln.get('version', '')}</h3>
                                </div>
                                <div class="flex items-center mt-2 space-x-3">
                                    <span class="text-sm text-gray-500">{vuln.get('title', 'N/A')}</span>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {color_classes.get('badge_bg', 'bg-gray-100')} {color_classes.get('badge_text', 'text-gray-800')}">
                                        CVSS: {cvss_score}
                                    </span>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                                        Published: {vuln.get('published', 'N/A')}
                                    </span>
                                </div>
                            </div>
                        </div>

                        <!-- Core Information Sections -->
                        <div class="space-y-6">
                            <!-- What's Wrong section -->
                            <div class="bg-gray-50 p-5 rounded-lg border border-gray-100">
                                <h4 class="font-semibold text-lg text-gray-800 flex items-center">
                                    <svg class="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    What's the problem?
                                </h4>
                                <p class="text-gray-700 mt-2">{parts['what'] or 'Vulnerability explanation not available.'}</p>
                            </div>

                            <!-- Potential Impact section -->
                            <div class="bg-gray-50 p-5 rounded-lg border border-gray-100">
                                <h4 class="font-semibold text-lg text-gray-800 flex items-center">
                                    <svg class="w-5 h-5 mr-2 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                                    </svg>
                                    Potential Impact
                                </h4>
                '''

                # Handle impact text formatting
                impact_text = parts['impact']
                if '\n' in impact_text:
                    impact_lines = [
                        re.sub(r'^[-•]\s*', '', line.strip())
                        for line in impact_text.split('\n')
                        if line.strip()
                    ]
                    
                    vul_block += '''
                        <ul class="mt-2 space-y-2">
                    '''
                    for line in impact_lines:
                        vul_block += f'''
                                    <li class="flex items-start">
                                        <svg class="w-4 h-4 text-red-500 mr-2 mt-1.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                                        </svg>
                                        <span>{line}</span>
                                    </li>
                        '''
                    vul_block += '''
                                </ul>
                    '''
                else:
                    vul_block += f'''
                                <p class="text-gray-700 mt-2">{impact_text or 'Impact information not available.'}</p>
                    '''
                
                vul_block += '''
                            </div>

                            <!-- Remediation Steps -->
                            <div class="bg-green-50 p-5 rounded-lg border border-green-200">
                                <h4 class="font-semibold text-lg text-gray-800 flex items-center">
                                    <svg class="w-5 h-5 mr-2 text-green-600" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                                    </svg>
                                    Steps to Fix it
                                </h4>
                '''
                
                # Handle fix text formatting
                fix_text = parts['fix']
                if '\n' in fix_text:
                    fix_lines = [line.strip() for line in fix_text.split('\n') if line.strip()]
                    vul_block += '''
                        <ol class="mt-2 space-y-2 list-none">
                    '''
                    for i, line in enumerate(fix_lines, 1):
                        # Remove numbered prefix like '1.', '2.', etc.
                        clean_line = re.sub(r'^\d+\.\s*', '', line)
                        vul_block += f'''
                            <li class="flex items-start">
                                <div class="flex items-center justify-center bg-green-100 rounded-full w-6 h-6 mt-1.5 mr-3 flex-shrink-0">
                                    <span class="text-green-700 font-bold text-xs">{i}</span>
                                </div>
                                <span>{clean_line}</span>
                            </li>
                        '''
                    vul_block += '''
                        </ol>
                    '''
                else:
                    vul_block += f'''
                        <p class="text-gray-700 mt-2">{fix_text or 'Remediation steps not available.'}</p>
                    '''
                
                vul_block += f'''
                            </div>

                            <!-- References -->
                            <div class="bg-gray-50 p-5 rounded-lg border border-gray-200">
                                <h4 class="font-semibold text-lg text-gray-800 flex items-center">
                                    <svg class="w-5 h-5 mr-2 text-gray-600" fill="currentColor" viewBox="0 0 20 20">
                                        <path d="M9 4.804A7.968 7.968 0 005.5 4c-1.255 0-2.443.29-3.5.804v10A7.969 7.969 0 015.5 14c1.669 0 3.218.51 4.5 1.385A7.962 7.962 0 0114.5 14c1.255 0 2.443.29 3.5.804v-10A7.968 7.968 0 0014.5 4c-1.255 0-2.443.29-3.5.804V12a1 1 0 11-2 0V4.804z"></path>
                                    </svg>
                                    Reference
                                </h4>
                                <div class="mt-3 space-y-2 text-sm">
                                    <a href="{vuln.get('href', '#')}" target="_blank" class="block text-blue-600 hover:underline">
                                        <div class="flex items-center">
                                            <svg class="w-4 h-4 mr-2 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
                                                <path d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z"></path>
                                                <path d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z"></path>
                                            </svg>
                                            {vuln.get('href', 'No reference available')}
                                        </div>
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                '''
            
            # Close the vulnerabilities container
            vul_block += '''
                </div>
            '''
        
        # Close the vulnerability details and section
        vul_block += '''
            </div>
        </div>
        '''
    
    # Close the main container
    vul_block += '''
    </div>
    '''
    # Final HTML with improved design
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Vulnerability Report</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@300..700&display=swap" rel="stylesheet">
        <style>
            body {{
                font-family: 'Quicksand', sans-serif;
            }}
            
            @media print {{
                .no-print {{
                    display: none;
                }}
            }}
            
            .stat-card {{
                transition: all 0.3s ease;
            }}

            .stat-card:hover {{
                transform: translateY(-5px);
            }}

            .icon-pulse {{
                animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
            }}

            @keyframes pulse {{
                0%, 100% {{
                    opacity: 1;
                }}
                50% {{
                    opacity: 0.7;
                }}
            }}
        </style>
    </head>
    <body class="bg-gray-50 leading-relaxed">
        <!-- The header section -->
        <header class="relative overflow-hidden bg-gradient-to-r from-indigo-800 via-blue-800 to-blue-900 text-white py-10 shadow-xl">
            <!-- Background Pattern -->
            <div class="absolute inset-0 opacity-10">
                <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <pattern id="header-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                            <path d="M 0 10 L 40 10 M 10 0 L 10 40" stroke="white" stroke-width="0.5" fill="none" />
                        </pattern>
                    </defs>
                    <rect width="100%" height="100%" fill="url(#header-grid)" />
                </svg>
            </div>

            <!-- Decorative Elements -->
            <div class="absolute -bottom-6 -left-6 w-32 h-32 bg-blue-500 rounded-full opacity-20 blur-2xl"></div>
            <div class="absolute top-10 right-10 w-24 h-24 bg-indigo-500 rounded-full opacity-20 blur-xl"></div>

            <div class="max-w-6xl mx-auto px-4 relative z-10">
                <div class="flex flex-col md:flex-row items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="bg-white/10 backdrop-blur-sm p-3 rounded-xl border border-white/20 shadow-lg">
                            <svg class="w-12 h-12 text-blue-100" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                    stroke-width="2"
                                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                                ></path>
                            </svg>
                        </div>
                        <div>
                            <h1 class="text-4xl font-bold tracking-tight">Vulnerability Report</h1>
                            <div class="flex items-center mt-2 text-blue-100">
                                <p class="text-sm font-normal">Security assessment and remediation guide</p>
                            </div>
                        </div>
                    </div>

                    <div class="mt-6 md:mt-0 flex flex-col items-end">
                        <div class="bg-white/10 backdrop-blur-sm p-4 rounded-xl border border-white/20 shadow-lg">
                            <div class="flex items-center space-x-3 mb-2">
                                <svg class="w-5 h-5 text-blue-200" fill="currentColor" viewBox="0 0 20 20">
                                    <path
                                        fill-rule="evenodd"
                                        d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z"
                                        clip-rule="evenodd"
                                    ></path>
                                </svg>
                                <span class="text-sm font-medium">Generated on {datetime.datetime.now().strftime("%d %B %Y at %I:%M %p")}</span>
                            </div>
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path>
                                    </svg>
                                    <span class="text-sm">Total vulnerabilities:</span>
                                </div>
                                <span class="ml-2 bg-red-500/80 text-white px-3 py-1 rounded-full text-sm font-medium shadow-sm">{total_vulnerabilities}</span>
                            </div>
                        </div>

                        <div class="flex mt-3 space-x-2 text-xs">
                            <div class="flex items-center">
                                <div class="w-3 h-3 rounded-full bg-red-500 mr-1"></div>
                                <span>Critical: {severity_counts["Critical"]}</span>
                            </div>
                            <div class="flex items-center">
                                <div class="w-3 h-3 rounded-full bg-orange-500 mr-1"></div>
                                <span>High: {severity_counts["High"]}</span>
                            </div>
                            <div class="flex items-center">
                                <div class="w-3 h-3 rounded-full bg-yellow-500 mr-1"></div>
                                <span>Medium: {severity_counts["Medium"]}</span>
                            </div>
                            <div class="flex items-center">
                                <div class="w-3 h-3 rounded-full bg-blue-500 mr-1"></div>
                                <span>Low: {severity_counts["Low"]}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </header>
        <!-- The header section ends -->
        
        <main class="max-w-6xl mx-auto px-4 py-8">
            <!-- system summary -->
            <div class="bg-white rounded-xl shadow-lg p-6 mb-8 border border-gray-100 transform transition-all duration-300 hover:shadow-xl" x-data="{{ expanded: false }}">
                <!-- Header with Toggle Button -->
                <div class="flex items-center justify-between cursor-pointer" @click="expanded = !expanded">
                    <div class="flex items-center space-x-4">
                        <div class="bg-gradient-to-br from-blue-50 to-blue-100 p-4 rounded-xl border border-blue-200 shadow-sm">
                            <svg class="w-10 h-10 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                        </div>
                        <div>
                            <h2 class="text-2xl font-bold text-gray-800 flex items-center">
                                System Summary
                                <span class="ml-2 text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">Security Analysis</span>
                            </h2>
                            <p class="text-gray-600" x-show="!expanded">Click to view detailed information about vulnerability risk categories and scoring system.</p>
                        </div>
                    </div>
                    <div class="flex items-center text-blue-600 font-medium">
                        <span x-text="expanded ? 'Hide Details' : 'Show Details'" class="mr-2 text-sm"></span>
                        <svg x-bind:class="expanded ? 'transform rotate-180' : ''" class="w-5 h-5 transition-transform duration-300" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                        </svg>
                    </div>
                </div>

                <!-- Expandable Content -->
                <div
                    x-show="expanded"
                    x-transition:enter="transition ease-out duration-300"
                    x-transition:enter-start="opacity-0 transform -translate-y-4"
                    x-transition:enter-end="opacity-100 transform translate-y-0"
                    x-transition:leave="transition ease-in duration-300"
                    x-transition:leave-start="opacity-100 transform translate-y-0"
                    x-transition:leave-end="opacity-0 transform -translate-y-4"
                    class="mt-6 pt-6 border-t border-gray-100"
                >
                    <!-- Description -->
                    <div class="mb-5">
                        <p class="text-gray-600 leading-relaxed">
                            This report provides an analysis of potential security vulnerabilities detected in your installed software. Each vulnerability has been categorized according to industry-standard RISK scores to help you prioritize your remediation efforts effectively.
                        </p>
                    </div>

                    <!-- RISK Score Categories -->
                    <div class="bg-gradient-to-r from-blue-50 to-indigo-50 p-5 rounded-xl border border-blue-100 shadow-sm">
                        <h3 class="text-lg font-semibold mb-4 text-blue-700 flex items-center">
                            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                            </svg>
                            RISK Score Categories
                        </h3>

                        <div class="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                            <!-- Critical -->
                            <div class="flex items-start space-x-3 p-3 bg-white rounded-lg border border-red-300 transition-transform hover:scale-105">
                                <span class="w-4 h-4 rounded-full bg-red-500 flex-shrink-0 mt-1"></span>
                                <div class="flex flex-col">
                                    <strong class="text-red-600 text-base">Critical (9.0-10.0)</strong>
                                    <span class="text-sm text-red-500 mt-0.5">Urgent attention required</span>
                                </div>
                            </div>

                            <!-- High -->
                            <div class="flex items-start space-x-3 p-3 bg-white rounded-lg border border-orange-300 transition-transform hover:scale-105">
                                <span class="w-4 h-4 rounded-full bg-orange-500 flex-shrink-0 mt-1"></span>
                                <div class="flex flex-col">
                                    <strong class="text-orange-600 text-base">High (7.0-8.9)</strong>
                                    <span class="text-sm text-orange-500 mt-0.5">Significant risk to security</span>
                                </div>
                            </div>

                            <!-- Medium -->
                            <div class="flex items-start space-x-3 p-3 bg-white rounded-lg border border-yellow-300 transition-transform hover:scale-105">
                                <span class="w-4 h-4 rounded-full bg-yellow-500 flex-shrink-0 mt-1"></span>
                                <div class="flex flex-col">
                                    <strong class="text-yellow-600 text-base">Medium (4.0-6.9)</strong>
                                    <span class="text-sm text-yellow-500 mt-0.5">Moderate risk to security</span>
                                </div>
                            </div>

                            <!-- Low -->
                            <div class="flex items-start space-x-3 p-3 bg-white rounded-lg border border-blue-300 transition-transform hover:scale-105">
                                <span class="w-4 h-4 rounded-full bg-blue-500 flex-shrink-0 mt-1"></span>
                                <div class="flex flex-col">
                                    <strong class="text-blue-600 text-base">Low (0.1-3.9)</strong>
                                    <span class="text-sm text-blue-500 mt-0.5">Limited risk to security</span>
                                </div>
                            </div>
                        </div>

                        <!-- Additional Information -->
                        <div class="mt-4 bg-white/70 p-3 rounded-lg border border-blue-100 text-sm text-gray-600">
                            <div class="flex items-start">
                                <svg class="w-5 h-5 text-blue-500 mr-2 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path>
                                </svg>
                                <div>
                                    <p class="font-medium text-blue-700">About CVSS Scores</p>
                                    <p class="mt-1">
                                        The Common Vulnerability Scoring System (CVSSv3) provides a standardized method for rating IT vulnerabilities. Higher scores indicate greater severity and should be prioritized for remediation.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Methodology Section -->
                    <div class="mt-5 bg-gray-50 p-4 rounded-xl border border-gray-200">
                        <h3 class="text-lg font-semibold mb-3 text-gray-700 flex items-center">
                            <svg class="w-5 h-5 mr-2 text-gray-600" fill="currentColor" viewBox="0 0 20 20">
                                <path
                                    fill-rule="evenodd"
                                    d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 0l-2 2a1 1 0 101.414 1.414L8 10.414l1.293 1.293a1 1 0 001.414 0l4-4z"
                                ></path>
                            </svg>
                            Assessment Methodology
                        </h3>
                        <p class="text-sm text-gray-600">
                            This report was generated using the Vulners API to identify vulnerabilities based on the software name and version. Once a vulnerability was detected, the tool utilized ChatGPT to generate a report that includes a summary of the vulnerability, its potential impact, and practical remediation steps.
                        </p>
                    </div>
                </div>
            </div>
            {dashboard}
            {vul_block}
        </main>
        <footer class="mt-12 relative">
            <!-- Main Footer Content -->
            <div class="bg-gray-900 text-gray-300 py-6 relative overflow-hidden">
                <!-- Decorative Elements -->
                <div class="absolute -bottom-10 right-10 w-40 h-40 bg-blue-500 rounded-full opacity-10 blur-3xl"></div>
                <div class="absolute bottom-5 left-10 w-32 h-32 bg-indigo-500 rounded-full opacity-10 blur-2xl"></div>

                <!-- Background Pattern -->
                <div class="absolute inset-0 opacity-5">
                    <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%">
                        <defs>
                            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                                <path d="M 0 10 L 40 10 M 10 0 L 10 40" stroke="white" stroke-width="0.5" fill="none" />
                            </pattern>
                        </defs>
                        <rect width="100%" height="100%" fill="url(#grid)" />
                    </svg>
                </div>

                <div class="max-w-6xl mx-auto px-4 relative z-10">
                    <!-- Minimal Content Layout -->
                    <div class="flex flex-col space-y-4">
                        <!-- Top Row: Brand and Print Button -->
                        <div class="flex flex-col sm:flex-row justify-between items-center pb-4 border-b border-gray-800">
                            <div class="flex items-center mb-3 sm:mb-0">
                                <div class="bg-blue-600 p-1.5 rounded-md mr-2">
                                    <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                            stroke-width="2"
                                            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                                        ></path>
                                    </svg>
                                </div>
                                <h3 class="text-lg font-bold text-white">© {datetime.datetime.now().year} Tashi Tam'$</h3>
                            </div>

                            <!-- Print Button -->
                            <div class="no-print">
                                <button onclick="window.print()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium flex items-center transition-colors duration-200">
                                    <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                            stroke-width="2"
                                            d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"
                                        ></path>
                                    </svg>
                                    Print Report
                                </button>
                            </div>
                        </div>

                        <!-- Middle Row: AI Disclaimer -->
                        <div class="py-3 px-4 bg-gray-800/80 rounded-md border border-gray-700 backdrop-blur-sm flex items-start space-x-3">
                            <svg class="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                                <path
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                    stroke-width="1.5"
                                    d="M10.75 2.45c.7-.59 1.83-.59 2.51 0l1.58 1.35c.3.25.87.46 1.27.46h1.7c1.06 0 1.93.87 1.93 1.93v1.7c0 .4.21.96.46 1.26l1.35 1.58c.59.7.59 1.83 0 2.51l-1.35 1.58c-.25.3-.46.86-.46 1.26v1.7c0 1.06-.87 1.93-1.93 1.93h-1.7c-.4 0-.96.21-1.26.46l-1.58 1.35c-.7.59-1.83.59-2.51 0l-1.58-1.35c-.3-.25-.87-.46-1.26-.46H6.17c-1.06 0-1.93-.87-1.93-1.93v-1.71c0-.39-.2-.96-.45-1.25l-1.35-1.59c-.58-.69-.58-1.81 0-2.5l1.35-1.59c.25-.3.45-.86.45-1.25V6.2c0-1.06.87-1.93 1.93-1.93H7.9c.4 0 .96-.21 1.26-.46l1.59-1.36zM12 8.13v4.83"
                                ></path>
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.995 16h.009"></path>
                            </svg>
                            <div>
                                <span class="font-medium text-white">Disclaimer: AI-Generated Report</span>
                                <span class="text-gray-300 text-sm ml-1">This report was generated using AI technology. Verify findings with trusted sources before taking action.</span>
                            </div>
                        </div>

                        <!-- Bottom Row: Additional Info -->
                        <div class="flex flex-col sm:flex-row justify-between items-center pt-2 text-xs text-gray-500">
                            <p>For educational purposes only</p>
                            <p>Security is a continuous process, not a one-time event.</p>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    </body>
    </html>
    """

    # Save the report
    report_path = os.path.abspath("Vulnerability_Report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"{Fore.GREEN}{Style.BRIGHT}[SUCCESS] {Style.RESET_ALL} Report generated: {report_path}")
    webbrowser.open(f"file://{report_path}")


            
            
def main():
    init(autoreset=True)
    show_disclaimer()
    
    print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} Scanning installed programs...Please wait.")
    start_time = time.time()
    
    try: 
        programs = get_installed_programs()
        display_installed_programs(programs)
        vulnerable_programs = search_for_vulnerabilities(programs)
        
        if vulnerable_programs:
            summarized = summarize_vulnerabilities_with_openai(vulnerable_programs)
            generate_report(summarized)
        else:
            print(f"{Fore.BLUE}{Style.BRIGHT}[INFO] {Style.RESET_ALL} No vulnerabilities found to summarize.")
                
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {Style.RESET_ALL} {str(e)}")
        
    finally:
        print(f"{Fore.GREEN}{Style.BRIGHT}[SUCCESS] {Style.RESET_ALL} Completed in {time.time()-start_time:.2f} seconds\n")


if __name__ == "__main__":
    main()