import vt
client = vt.Client("f563b65ea14215881a51140d9babbeb253174afc1638375380d1ff490fb315c8")
analysis = client.scan_url('https://ynet.co.il', wait_for_completion=True)
print(analysis)
client.close()