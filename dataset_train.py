import requests
import json
import time
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import numpy as np

# Configuration
EXPLOIT_DB_URL = "https://exploit-db.com/search?author=&title=&platform=router&port=&type=&cve="
VENDOR_ADVISORIES = {
    "Cisco": "https://tools.cisco.com/security/center/publicationListing.x",
    "Netgear": "https://www.netgear.com/support/",
    "TP-Link": "https://www.tp-link.com/us/support/download/"
}

# Function to fetch data from NVD API with improved error handling
def fetch_nvd_data(keywordSearch="router", results_per_page=200):
    """
    Fetch vulnerability data from NVD API with better error handling.
    
    Args:
        keyword (str): Search keyword for vulnerabilities
        results_per_page (int): Number of results per API call
        
    Returns:
        list: List of vulnerability dictionaries
    """
    vulnerabilities = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    try:
        # First request to get total results
        params = {
            "keywordSearch": keywordSearch,
            "resultsPerPage": 1
        }
        
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise exception for bad status
        
        total_results = response.json().get("totalResults", 0)
        print(f"Total vulnerabilities found: {total_results}")
        
        # Paginate through results
        for start_index in range(0, total_results, results_per_page):
            params = {
                "keywordSearch": keywordSearch,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            
            response = requests.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                description = next((desc.get('value', '') for desc in cve.get('descriptions', []) if desc.get('lang') == 'en'), '')
                cvss_score = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0.0)
                
                cpe_entries = []
                configurations = cve.get('configurations', {}).get('nodes', [])
                if isinstance(configurations, list):
                    for config in configurations:
                        if isinstance(config, dict):
                            cpe_entries.extend([cpe.get('cpe23Uri', '') for cpe in config.get('cpeMatch', [])])
                
                vulnerabilities.append({
                    "CVE_ID": cve_id,
                    "Description": description,
                    "CVSS_Score": cvss_score,
                    "CPE_Entries": cpe_entries,
                    "Published_Date": cve.get('published', ''),
                    "Last_Modified_Date": cve.get('lastModified', '')
                })
            time.sleep(6)  # Respect NVD API rate limits
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data: {e}")
    except json.JSONDecodeError as e:
        print(f"Error decoding NVD response: {e}")
    except KeyError as e:
        print(f"Unexpected response format from NVD: {e}")
    
    return vulnerabilities

# Function to scrape vendor advisories
def scrape_vendor_advisories():
    """
    Scrape vulnerability advisories from vendor websites.
    
    Returns:
        list: List of advisory dictionaries
    """
    advisories = []
    
    # Example implementation for Cisco
    cisco_url = VENDOR_ADVISORIES["Cisco"]
    try:
        response = requests.get(cisco_url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        
        if table:
            for row in table.find_all('tr')[1:]:  # Skip header
                columns = row.find_all('td')
                if len(columns) >= 2:
                    cve_id = columns[0].text.strip()
                    advisory_link = columns[1].find('a')['href'] if columns[1].find('a') else ''
                    advisories.append({
                        "Vendor": "Cisco",
                        "CVE_ID": cve_id,
                        "Advisory_Link": advisory_link
                    })
    except requests.exceptions.RequestException as e:
        print(f"Failed to scrape Cisco advisories: {e}")
    except Exception as e:
        print(f"Error scraping Cisco advisories: {e}")
    
    # Add similar logic for other vendors
    
    return advisories

# Function to scrape exploit database
def scrape_exploit_db():
    """
    Scrape exploit information from Exploit-DB.
    
    Returns:
        list: List of exploit dictionaries
    """
    exploits = []
    try:
        response = requests.get(EXPLOIT_DB_URL)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all exploit entries
        for entry in soup.select('.exploit-table__body tr'):
            columns = entry.select('td')
            
            if len(columns) >= 4:
                title = columns[0].text.strip()
                cve_id = columns[1].text.strip()
                platform = columns[2].text.strip()
                type = columns[3].text.strip()
                link = columns[0].find('a')['href'] if columns[0].find('a') else ''
                
                exploits.append({
                    "Title": title,
                    "CVE_ID": cve_id,
                    "Platform": platform,
                    "Type": type,
                    "Link": link
                })
    except requests.exceptions.RequestException as e:
        print(f"Failed to scrape Exploit-DB: {e}")
    except Exception as e:
        print(f"Error scraping Exploit-DB: {e}")
    
    return exploits

# Function to process CPE entries
def process_cpe(cpe_uri):
    """
    Process a CPE URI to extract manufacturer, model, and version information.
    
    Args:
        cpe_uri (str): CPE URI in CPE 2.3 format
        
    Returns:
        dict: Dictionary with manufacturer, model, and version
    """
    parts = cpe_uri.split(':')
    if len(parts) >= 5:
        return {
            "Manufacturer": parts[3],
            "Model": parts[4],
            "Version": parts[5] if len(parts) > 5 else "any"
        }
    return {
        "Manufacturer": "",
        "Model": "",
        "Version": ""
    }

# Function to merge data sources with safety checks
def merge_data_sources(nvd_data, advisories, exploits):
    """
    Merge data from different sources into a unified dataset with safety checks.
    
    Args:
        nvd_data (list): List of NVD vulnerability dictionaries
        advisories (list): List of vendor advisory dictionaries
        exploits (list): List of exploit dictionaries
        
    Returns:
        pandas.DataFrame: Merged dataset or None if merge failed
    """
    try:
        # Convert to DataFrames
        df_nvd = pd.DataFrame(nvd_data)
        df_advisories = pd.DataFrame(advisories)
        df_exploits = pd.DataFrame(exploits)
        
        # Check if required columns exist
        if 'CVE_ID' not in df_nvd.columns:
            print("Error: NVD data is missing CVE_ID column")
            return None
        
        # Merge NVD with advisories on CVE_ID
        df_merged = pd.merge(df_nvd, df_advisories, on='CVE_ID', how='left')
        
        # Merge with exploits on CVE_ID
        df_merged = pd.merge(df_merged, df_exploits, on='CVE_ID', how='left')
        
        # Process CPE entries
        cpe_data = []
        for cpe_list in df_merged['CPE_Entries']:
            if not cpe_list:
                cpe_data.append({"Manufacturer": "", "Model": "", "Version": ""})
            else:
                # Process first CPE entry (you might want to process all)
                cpe_info = process_cpe(cpe_list[0])
                cpe_data.append(cpe_info)
        
        df_cpe = pd.DataFrame(cpe_data)
        df_merged = pd.concat([df_merged, df_cpe], axis=1)
        
        # Create 'Exploit_Available' flag
        df_merged['Exploit_Available'] = np.where(df_merged['Link'].notnull(), 1, 0)
        
        # Select relevant columns
        final_columns = [
            'CVE_ID', 'Description', 'CVSS_Score', 'Published_Date', 
            'Manufacturer', 'Model', 'Version', 'Exploit_Available', 'Link'
        ]
        
        return df_merged[final_columns]
    
    except KeyError as e:
        print(f"Merge failed due to missing column: {e}")
        return None
    except Exception as e:
        print(f"Error merging data sources: {e}")
        return None

# Function to preprocess data for ML
def preprocess_for_ml(df):
    """
    Preprocess dataset for machine learning.
    
    Args:
        df (pandas.DataFrame): Input dataset
        
    Returns:
        pandas.DataFrame: Preprocessed dataset
    """
    if df is None or df.empty:
        print("No data to preprocess")
        return None
    
    try:
        # Handle missing values
        df.fillna({
            'Description': '',
            'Link': '',
            'Manufacturer': '',
            'Model': '',
            'Version': ''
        }, inplace=True)
        
        # Convert dates to datetime objects
        df['Published_Date'] = pd.to_datetime(df['Published_Date'])
        
        # Feature engineering
        df['Description_Length'] = df['Description'].apply(len)
        df['Days_Since_Publication'] = (datetime.now() - df['Published_Date']).dt.days
        
        # Drop non-numeric columns that aren't features
        df.drop(['Description', 'CVE_ID', 'Link', 'Published_Date'], axis=1, inplace=True)
        
        # Encode categorical variables
        categorical_features = ['Manufacturer', 'Model', 'Version']
        numeric_features = ['CVSS_Score', 'Description_Length', 'Days_Since_Publication']
        
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
            ])
        
        # Fit and transform the data
        processed_data = preprocessor.fit_transform(df)
        
        return pd.DataFrame(processed_data.toarray())
    
    except Exception as e:
        print(f"Error preprocessing data: {e}")
        return None

# Main execution
if __name__ == "__main__":
    # Step 1: Collect data from various sources
    print("Collecting data from NVD...")
    nvd_data = fetch_nvd_data()
    
    print("Scraping vendor advisories...")
    advisories = scrape_vendor_advisories()
    
    print("Scraping exploit database...")
    exploits = scrape_exploit_db()
    
    # Step 2: Merge data sources
    print("Merging data sources...")
    merged_df = merge_data_sources(nvd_data, advisories, exploits)
    
    if merged_df is not None and not merged_df.empty:
        # Step 3: Preprocess for ML
        print("Preprocessing data for machine learning...")
        ml_ready_df = preprocess_for_ml(merged_df.copy())
        
        # Step 4: Save datasets
        merged_df.to_csv('router_vulnerabilities_raw.csv', index=False)
        if ml_ready_df is not None:
            ml_ready_df.to_csv('router_vulnerabilities_ml_ready.csv', index=False)
        
        print("Dataset creation complete!")
        print(f"Raw dataset saved to router_vulnerabilities_raw.csv")
        if ml_ready_df is not None:
            print(f"ML-ready dataset saved to router_vulnerabilities_ml_ready.csv")
    else:
        print("No data to save. Dataset creation failed.")