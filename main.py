import os
import requests
import time

upload_url = "https://www.virustotal.com/api/v3/files"
api_key = "ef7eaeadf74ef721a6d3578e2b4aaa824358c6d2c5a2921b6ce66f9b23658607"

def AntiVirus(path):
    if "." in path:
        ScanFile(path)
        return
    dir_list = os.listdir(path)
    print("Files and directories in '", path, "' :")
    print(dir_list)
    for i in dir_list:
        AntiVirus(path + "//" + i)

def ScanFile(path):
    headers = {
        'x-apikey': api_key,
    }

    with open(path, 'rb') as file:
        files = {'file': file}
        response = requests.post(upload_url, headers=headers, files=files)

    if response.status_code == 200:
        file_id = response.json()['data']['id']
    else:
        print(f"Error: {response.status_code}")
        print(response.json())
        file_id = None

    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            status = result['data']['attributes']['status']
            if status == 'completed':
                PrintResult(result, path)
                break
            else:
                time.sleep(1)  # Wait for a while before checking again
        else:
            print(f"Error: {response.status_code}")
            print(response.json())
            print(None)
            break

def PrintResult(result, path):
    engines = list(result['data']['attributes']['results'].values())
    for i in engines:
        if i['result'] != None and i['result'] != "clean":
            print(path + " is probably virus")
            return
    print(path + " is probably safe")

def main():
    path = ("C://course//testFolder")
    while True:
        AntiVirus(path)
        time.sleep(5)

if __name__ == "__main__":
    main()