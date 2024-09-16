# File: elasticsearch_siem.py

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, NotFoundError, RequestError, AuthenticationException
import re
import time
import sys
import subprocess
import signal
import os
import requests
import json
from threading import Event

# Paths
es_bin_path = r"C:\Users\Fahad Ijaz\Downloads\elasticsearch-8.14.3-windows-x86_64\elasticsearch-8.14.3\bin"
logstash_bin_path = r"C:\Users\Fahad Ijaz\Downloads\logstash-8.14.3-windows-x86_64\logstash-8.14.3\bin"
logstash_config_dir = r"C:\Users\Fahad Ijaz\Downloads\logstash-8.14.3-windows-x86_64\logstash-8.14.3\config"

# Elasticsearch credentials
es_url = "http://localhost:9200"
es_username = "elastic"
es_password = "BUrYMhg*u2bf5pR8a1cn"

# Global process handles
es_process = None
logstash_process = None
stop_event = Event()

def start_elasticsearch():
    global es_process
    print("Starting Elasticsearch...")
    
    es_cmd = f'start cmd /k "cd /d {es_bin_path} && elasticsearch.bat"'
    es_process = subprocess.Popen(es_cmd, shell=True)

    # Wait for Elasticsearch to become available
    while not is_elasticsearch_up():
        print("Waiting for Elasticsearch to start...")
        time.sleep(5)
    
    print("Elasticsearch started successfully.")

def is_elasticsearch_up():
    try:
        response = requests.get(es_url, auth=(es_username, es_password))
        return response.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def connect_to_elasticsearch(host='localhost', port=9200, scheme='http', username=None, password=None):
    try:
        es = Elasticsearch(
            hosts=[{'host': host, 'port': port, 'scheme': scheme}],
            basic_auth=(username, password) if username and password else None
        )
        if es.ping():
            print("Connected to Elasticsearch")
        else:
            print("Could not connect to Elasticsearch")
        return es
    except ConnectionError as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return None
    except AuthenticationException as e:
        print(f"Authentication error: {e}")
        return None

def list_indices(es):
    try:
        indices = es.indices.get_alias(index="*")
        print("Available indices:")
        for idx, index_name in enumerate(indices.keys(), start=1):
            print(f"{idx}. {index_name}")
        return list(indices.keys())
    except ConnectionError as e:
        print(f"Connection error while listing indices: {e}")
        return []
    except AuthenticationException as e:
        print(f"Authentication error while listing indices: {e}")
        return []

def delete_index(es, index_name):
    try:
        es.indices.delete(index=index_name)
        print(f"Index {index_name} deleted successfully.")
    except NotFoundError:
        print(f"Index {index_name} not found.")
    except ConnectionError as e:
        print(f"Error deleting index: {e}")

def extract_fields(log_type, message):
    if isinstance(message, list):
        message = ' '.join(message)

    if log_type == "System":
        pattern = re.compile(r"bootid: (?P<boot_id>\d+), resumecount: (?P<resume_count>\d+), fullresume: (?P<full_resume>\d+), averageresume: (?P<average_resume>\d+), suspendstart: (?P<suspend_start>\d+), suspendend: (?P<suspend_end>\d+)")
    elif log_type == "Application":
        pattern = re.compile(r"Faulting application name: (?P<faulting_application_name>.+?), Faulting module name: (?P<faulting_module_name>.+?), Exception code: (?P<exception_code>.+?), Faulting process id: (?P<faulting_process_id>\d+), Faulting application path: (?P<faulting_application_path>.+?), Faulting module path: (?P<faulting_module_path>.+?), Report Id: (?P<report_id>.+?), Problem signature: (?P<problem_signature>.+)")

    elif log_type == "Security":
        pattern = re.compile(r"Provider Name: (?P<providername>.+?), New Provider State: (?P<newproviderstate>.+?), Sequence Number: (?P<sequencenumber>\d+), Hostname: (?P<hostname>.+?), Host Version: (?P<hostversion>.+?), Host Id: (?P<hostid>.+?), Host Application: (?P<hostapplication>.+?), Engine Version: (?P<engineversion>.+?), Runspace Id: (?P<runspaceid>.+?), Pipeline Id: (?P<pipelineid>.+?), Command Name: (?P<commandname>.+?), Command Type: (?P<commandtype>.+?), Script Name: (?P<scriptname>.+?), Command Path: (?P<commandpath>.+?), Command Line: (?P<commandline>.+)")
    else:
        return {}

    match = pattern.search(message)
    return match.groupdict() if match else {}

def query_elasticsearch(es, index, query_body):
    try:
        response = es.search(index=index, body=query_body)
        return response
    except NotFoundError as e:
        print(f"Index not found: {e}")
        return None
    except RequestError as e:
        print(f"Error in the search request: {e}")
        return None
    except ConnectionError as e:
        print(f"Connection error while querying Elasticsearch: {e}")
        return None
    except AuthenticationException as e:
        print(f"Authentication error while querying Elasticsearch: {e}")
        return None

def display_results_as_list(response):
    if response:
        hits = response['hits']['hits']
        
        for hit in hits:
            source = hit.get('_source', {})
            log_type = source.get('log_type', 'N/A')
            extracted_fields = extract_fields(log_type, source.get('message', ''))

            print(f"@timestamp: {source.get('@timestamp', 'N/A')}")
            print(f"current_timestamp: {source.get('current_timestamp', 'N/A')}")
            print(f"event_source: {source.get('event_source', 'N/A')}")
            print(f"event_timestamp: {source.get('event_timestamp', 'N/A')}")
            print(f"event_type: {source.get('event_type', 'N/A')}")
            print(f"log_type: {log_type}")
            
            for key, value in extracted_fields.items():
                print(f"{key}: {value or 'N/A'}")
            
            print(f"normalized_message: {source.get('normalized_message', 'N/A')}")
            print(f"severity_level: {source.get('severity_level', 'N/A')}")
            print(f"tags: {source.get('tags', 'N/A')}")
            print("----")
    else:
        print("No results found or an error occurred")

def start_logstash(config_file):
    global logstash_process
    print(f"Starting Logstash with config: {config_file}")
    
    # Ensure paths are enclosed in double quotes to handle spaces in paths
    logstash_cmd = f'start cmd /k "cd /d {logstash_bin_path} && logstash.bat -f \"{config_file}\""'
    
    try:
        # Start Logstash in a new terminal window
        logstash_process = subprocess.Popen(logstash_cmd, shell=True)
        print("Logstash started in a new terminal window.")
    except Exception as e:
        print(f"Error starting Logstash: {e}")

def stop_logstash():
    global logstash_process
    if logstash_process:
        logstash_process.terminate()
        logstash_process = None
        print("Logstash stopped.")

def main_menu():
    print("Options Menu:")
    print("1) View Indices")
    print("2) Delete Indices")
    print("3) Start Logstash")
    print("4) Exit")

def main():
    start_elasticsearch()

    es = connect_to_elasticsearch(host="localhost", port=9200, scheme="http", username="elastic", password="BUrYMhg*u2bf5pR8a1cn")
    if not es:
        print("Elasticsearch connection failed. Exiting.")
        return

    while True:
        main_menu()
        choice = input("Choose an option: ")

        if choice == '1':  # View Indices
            indices = list_indices(es)
            if indices:
                while True:
                    selected_index = input("Enter index number to view (or 'q' to quit): ")
                    if selected_index == 'q':
                        break
                    try:
                        idx_num = int(selected_index) - 1
                        if 0 <= idx_num < len(indices):
                            index = indices[idx_num]
                            query_body = {"query": {"match_all": {}}}
                            response = query_elasticsearch(es, index, query_body)
                            display_results_as_list(response)
                        else:
                            print("Invalid index number.")
                    except ValueError:
                        print("Please enter a valid number.")
        
        elif choice == '2':  # Delete Indices
            indices = list_indices(es)
            if indices:
                while True:
                    selected_index = input("Enter index number to delete (or 'q' to quit): ")
                    if selected_index == 'q':
                        break
                    try:
                        idx_num = int(selected_index) - 1
                        if 0 <= idx_num < len(indices):
                            index = indices[idx_num]
                            confirm = input(f"Are you sure you want to delete {index}? (y/n): ")
                            if confirm.lower() == 'y':
                                delete_index(es, index)
                        else:
                            print("Invalid index number.")
                    except ValueError:
                        print("Please enter a valid number.")

        elif choice == '3':  # Start Logstash
            logstash_configs = [f for f in os.listdir(logstash_config_dir) if f.endswith('.conf')]
            if logstash_configs:
                print("Available Logstash config files:")
                for idx, config in enumerate(logstash_configs, start=1):
                    print(f"{idx}. {config}")
                selected_config = input("Enter config file number to start Logstash (or 'q' to quit): ")
                if selected_config == 'q':
                    continue
                try:
                    config_idx = int(selected_config) - 1
                    if 0 <= config_idx < len(logstash_configs):
                        config_file = os.path.join(logstash_config_dir, logstash_configs[config_idx])
                        start_logstash(config_file)
                    else:
                        print("Invalid config file number.")
                except ValueError:
                    print("Please enter a valid number.")

            while True:
                action = input("Enter 'stop' to stop Logstash or 'q' to go back: ").lower()
                if action == 'stop':
                    stop_logstash()
                    break
                elif action == 'q':
                    break

        elif choice == '4':  # Exit
            if logstash_process:
                stop_logstash()
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
