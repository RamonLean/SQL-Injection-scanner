import requests
# import re # uncomment this for DVWA
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def Localiza_forms(url):
    """Localiza os "forms" do conteúdo HTML."""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def Detalhes_form(form):
    """
    Extrai informações úteis do "form" HTML.
    """
    detalhes= {}
    # get the form action (target url)
    try:
        acao = form.attrs.get("action").lower()
    except:
        acao = None
    # Pega o método do form (POST, GET, etc.)
    metodo = form.attrs.get("method", "get").lower()
    # Pega detalhes de entrada, como  tipo e nome.
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    detalhes["action"] = acao
    detalhes["method"] = metodo
    detalhes["inputs"] = inputs
    return detalhes


def Vulneravel(response):
    """ Funão booleana simples que determina se a uma página é vulneravel
    a SQL Injection a depender da resposta"""
    erros = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for erro in erros:
        # Se encontra algum dos erros especificados em "erros", retorna verdadeira
        if erro in response.content.decode().lower():
            return True
    # Sem erro detectado
    return False


def scan_sql_injection(url):
    # Testar a URL
    for c in "\"'":
        # Adiciona apóstrofo simples e duplos a URL
        nova_url = f"{url}{c}"
        print("[!] Verificando", nova_url)
        # Faz a reequisição HTTP
        res = s.get(nova_url)
        if Vulneravel(res):
            # Vulnerabilidade de SQL Injection detectada, não é necessário formulários. 
            print("[+] Vulnerabilidade de SQL Injection detectada, link:", nova_url)
            return
    # Texto nos forms HTML
    forms = Localiza_forms(url)
    print(f"[+] Detectado {len(forms)} forms em {url}.")
    for form in forms:
        form_detalhes = Detalhes_form(form)
        for c in "\"'":
            # Dados que queremos enviar
            data = {}
            for input_tag in form_detalhes["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # Qualquer formúlario de entrada
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # Todos os outros por excessão de submit
                    data[input_tag["name"]] = f"test{c}"
            # URL de solicitação de formulário
            url = urljoin(url, form_details["action"])
            if form_detalhes["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # Testa se o retorno de página é vulnerável
            if Vulneravel(res):
                print("[+] Vulnerabilidade de SQL Injection detectada, link:", url)
                print("[+] Form:")
                print(form_detalhes)
                break   

if __name__ == "__main__":
    import sys
    #print (sys.argv[0])
    try:
        url = sys.argv[1]
        #print (sys.argv[1])
        scan_sql_injection(url)
    except:
        print("\nURL não inserida corretamente ou host não existe, \
exemplo de url válida: ""http://exemplo.com"", não se esqueça de utilizar http://")
    
