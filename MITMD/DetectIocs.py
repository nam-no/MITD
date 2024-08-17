import requests
from bs4 import BeautifulSoup

# Hàm lấy IOCs từ trang web ThreatFox
def get_threatfox_iocs():
    url = 'https://threatfox.abuse.ch/browse/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Tìm bảng chứa IOCs dựa trên id cụ thể hoặc các thuộc tính khác
    table = soup.find('table', {'id': 'iocs'})
    if table:
        rows = table.find_all('tr')[1:]  # Bỏ qua tiêu đề
        iocs = []
        for row in rows:
            cols = row.find_all('td')
            if len(cols) > 1:
                ioc = cols[1].find('a').text.strip()  # Trích xuất IOC từ thẻ <a> bên trong <td> thứ 2
                iocs.append(ioc)
        return iocs
    else:
        print("Không tìm thấy bảng chứa IOCs")
        return []

# Lấy IOCs từ trang web ThreatFox
threatfox_iocs = get_threatfox_iocs()

# In danh sách IOCs
print(f"ThreatFox IOCs: {threatfox_iocs}")