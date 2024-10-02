#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

echo -e "${BLUE}Advanced Vulnerability Scanner Tool${RESET}"
echo -e "${YELLOW}Copyright © $(date +%Y) FrogSec. All rights reserved.${RESET}"
read -p "Enter URL (e.g., http://example.com): " url


results_dir="results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$results_dir"


read -p "Enter SQL Injection payload wordlist path: " sql_injection_wordlist
read -p "Enter CSRF payload wordlist path: " csrf_payloads
read -p "Enter Open Redirect payloads wordlist path: " open_redirect_payloads
read -p "Enter Directory Traversal payloads wordlist path: " directory_traversal_payloads


sql_injection_results="$results_dir/sql_injection_results.txt"
csrf_results="$results_dir/csrf_results.txt"
open_redirect_results="$results_dir/open_redirect_results.txt"
directory_traversal_results="$results_dir/directory_traversal_results.txt"
security_headers_results="$results_dir/security_headers_results.txt"
google_dorks_results="$results_dir/google_dorks_results.txt"


get_custom_headers() {
    echo -e "${YELLOW}Enter custom headers (format: Header: Value), type 'done' when finished:${RESET}"
    headers=()
    while true; do
        read -p "Header: " header
        if [[ "$header" == "done" ]]; then
            break
        fi
        headers+=("$header")
    done
}


get_custom_headers


echo -e "\nStarting SQL Injection Scan..." | tee -a "$sql_injection_results"
while read -r payload; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${headers[@]/#/-H }" "$url$payload")
    if [[ "$response" == "200" || "$response" == "500" ]]; then
        echo -e "${RED}Possible SQL Injection: $url$payload (HTTP Status: $response)${RESET}" | tee -a "$sql_injection_results"
    fi
done < "$sql_injection_wordlist"


echo -e "\nStarting CSRF Scan..." | tee -a "$csrf_results"
while read -r payload; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${headers[@]/#/-H }" "$url" -d "$payload")
    if [[ "$response" == "200" ]]; then
        echo -e "${YELLOW}Possible CSRF Vulnerability: $url (HTTP Status: $response)${RESET}" | tee -a "$csrf_results"
    fi
done < "$csrf_payloads"


echo -e "\nStarting Open Redirect Scan..." | tee -a "$open_redirect_results"
while read -r redirect_url; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${headers[@]/#/-H }" "$url?redirect=$redirect_url")
    if [[ "$response" == "200" ]]; then
        echo -e "${GREEN}Possible Open Redirect: $url?redirect=$redirect_url (HTTP Status: $response)${RESET}" | tee -a "$open_redirect_results"
    fi
done < "$open_redirect_payloads"


echo -e "\nStarting Directory Traversal Scan..." | tee -a "$directory_traversal_results"
while read -r path; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "${headers[@]/#/-H }" "$url/$path")
    if [[ "$response" == "200" ]]; then
        echo -e "${RED}Possible Directory Traversal: $url/$path (HTTP Status: $response)${RESET}" | tee -a "$directory_traversal_results"
    fi
done < "$directory_traversal_payloads"


echo -e "\nChecking Security Headers..." | tee -a "$security_headers_results"
security_headers=("X-Content-Type-Options" "Content-Security-Policy" "X-XSS-Protection" "Strict-Transport-Security")
for header in "${security_headers[@]}"; do
    response=$(curl -s -I "${headers[@]/#/-H }" "$url" | grep -i "$header")
    if [ -z "$response" ]; then
        echo -e "${RED}Missing Security Header: $header${RESET}" | tee -a "$security_headers_results"
    else
        echo -e "${GREEN}Security Header Present: $header${RESET}" | tee -a "$security_headers_results"
    fi
done


echo -e "\nStarting Expanded Google Dorks Scan..." | tee -a "$google_dorks_results"


dorks=(
    "site:$url"
    "inurl:$url"
    "intitle:$url"
    "filetype:php site:$url"
    "intext:\"error\" site:$url"
    "inurl:login"
    "intitle:login"
    "filetype:config"
    "filetype:sql"
    "filetype:php inurl:config"
    "inurl:api"
    "filetype:pdf \"confidential\""
    "inurl:\".php?id=\""
)

for dork in "${dorks[@]}"; do
    echo -e "${BLUE}Query: $dork${RESET}" | tee -a "$google_dorks_results"

    
    results=$(curl -s "https://www.google.com/search?q=$dork" | grep -oP '(?<=<h3 class=").*?(?=</h3>)')
    
    if [ -n "$results" ]; then
        echo -e "${GREEN}Results: ${results}${RESET}" | tee -a "$google_dorks_results"
    else
        echo -e "${YELLOW}No results found.${RESET}" | tee -a "$google_dorks_results"
    fi
done


echo -e "${GREEN}\nScan complete. Results saved in folder: $results_dir${RESET}"
echo -e "${GREEN}"
cat << "EOF"
         _     _
        ( \---/ )
         \ o o /
          \ 0 /
           \_/
EOF
echo -e "${RESET}"
