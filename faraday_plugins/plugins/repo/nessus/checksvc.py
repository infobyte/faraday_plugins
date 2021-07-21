import http.client
import ssl

def is_https(target):
    try:
        ctx = ssl._create_unverified_context()
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        conn = http.client.HTTPSConnection(target, context=ctx, timeout=4)
        headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE5.01; Windows NT)'}
        conn.request(method="GET", url="/", headers=headers)
        var = conn.getresponse()
        return True
    except:
        return False

def is_http(target):
    try:
        conn = http.client.HTTPConnection(target, timeout=4)
        headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE5.01; Windows NT)'}
        conn.request(method="GET", url="/", headers=headers)
        var = conn.getresponse()
        return True
    except:
        return False
