#!/usr/bin/env python3
import asyncio
from camadafisica import ZyboSerialDriver
from tcp import Servidor        # copie o arquivo do T2
from ip import IP               # copie o arquivo do T3
from slip import CamadaEnlace   # copie o arquivo do T4
import re

## ============================================================================
## SERVIDOR IRC - Implementação da camada de aplicação
## ============================================================================

mapa_conexoes_usuario = {}
grupos_de_canais = {}

def validar_nome_de_recurso(nome):
    return re.match(br'^[a-zA-Z][a-zA-Z0-9_-]*$', nome) is not None

def remover_conexao(conexao_cliente):
    print(conexao_cliente, 'conexão fechada')
    estado_saindo = mapa_conexoes_usuario.get(conexao_cliente)

    if not estado_saindo or 'apelido' not in estado_saindo:
        if conexao_cliente in mapa_conexoes_usuario:
            del mapa_conexoes_usuario[conexao_cliente]
        conexao_cliente.fechar()
        return

    apelido_usuario = estado_saindo['apelido']
    membros_a_notificar = set()
    
    for membros in grupos_de_canais.values():
        if conexao_cliente in membros:
            for membro in membros:
                if membro != conexao_cliente:
                    membros_a_notificar.add(membro)

    msg_quit = b':' + apelido_usuario + b' QUIT :Connection closed\r\n'
    for membro in membros_a_notificar:
        try:
            membro.enviar(msg_quit)
        except (BrokenPipeError, OSError):
            pass

    for nome, membros in list(grupos_de_canais.items()):
        if conexao_cliente in membros:
            membros.remove(conexao_cliente)
            if not membros:
                del grupos_de_canais[nome]

    del mapa_conexoes_usuario[conexao_cliente]
    conexao_cliente.fechar()

def dados_recebidos(conexao, dados):
    if dados == b'':
        remover_conexao(conexao)
        return
    
    estado_usuario = mapa_conexoes_usuario[conexao]
    estado_usuario['buffer'] += dados

    while b'\r\n' in estado_usuario['buffer']:
        msg, msg_restante = estado_usuario['buffer'].split(b'\r\n', 1)
        estado_usuario['buffer'] = msg_restante
        processar_entrada(conexao, msg)

def conexao_aceita(conexao):
    print(conexao, 'nova conexão')
    mapa_conexoes_usuario[conexao] = {'buffer': b''}
    conexao.registrar_recebedor(dados_recebidos)

def processar_entrada(conexao, mensagem_completa):
    mensagem_completa = mensagem_completa.strip()
    if not mensagem_completa:
        return

    print(f"Processando: {mensagem_completa.decode(errors='ignore')}")

    partes_comando = mensagem_completa.split(b' ', 1)
    comando_principal = partes_comando[0].upper()
    argumentos = partes_comando[1] if len(partes_comando) > 1 else b''
    estado_cliente = mapa_conexoes_usuario[conexao]
    apelido_cliente = estado_cliente.get('apelido')

    if apelido_cliente is None and comando_principal not in [b'NICK', b'PING']:
        return
        
    if comando_principal == b'PING':
        handle_ping(conexao, argumentos)
    elif comando_principal == b'NICK':
        handle_nick(conexao, argumentos)
    elif comando_principal == b'JOIN':
        handle_join(conexao, argumentos)
    elif comando_principal == b'PART':
        handle_part(conexao, argumentos)
    elif comando_principal == b'PRIVMSG':
        handle_privmsg(conexao, argumentos)

def encontrar_conexao_por_apelido(apelido):
    apelido = apelido.lower()
    for conexao, estado in mapa_conexoes_usuario.items():
        if estado.get('apelido', b'').lower() == apelido:
            return conexao
    return None

def handle_ping(conexao, argumentos):
    conexao.enviar(b':server PONG server :' + argumentos + b'\r\n')

def handle_nick(conexao, argumentos):
    novo_apelido = argumentos.strip()
    estado_usuario = mapa_conexoes_usuario[conexao]
    apelido_atual = estado_usuario.get('apelido', b'*')

    if not validar_nome_de_recurso(novo_apelido):
        conexao.enviar(b':server 432 ' + apelido_atual + b' ' + novo_apelido + b' :Erroneous nickname\r\n')
        return
        
    conexao_existente = encontrar_conexao_por_apelido(novo_apelido)
    if conexao_existente and conexao_existente != conexao:
        conexao.enviar(b':server 433 ' + apelido_atual + b' ' + novo_apelido + b' :Nickname is already in use\r\n')
    else:
        if apelido_atual != b'*':
            membros_a_notificar = set()
            for membros in grupos_de_canais.values():
                if conexao in membros:
                    for membro in membros:
                        if membro != conexao:
                            membros_a_notificar.add(membro)
            
            msg_nick = b':' + apelido_atual + b' NICK ' + novo_apelido + b'\r\n'
            conexao.enviar(msg_nick)
            for membro in membros_a_notificar:
                membro.enviar(msg_nick)
        else:
            conexao.enviar(b':server 001 ' + novo_apelido + b' :Welcome\r\n')
            conexao.enviar(b':server 422 ' + novo_apelido + b' :MOTD File is missing\r\n')
        
        estado_usuario['apelido'] = novo_apelido

def handle_privmsg(conexao, argumentos):
    remetente = mapa_conexoes_usuario[conexao].get('apelido')
    if b' :' not in argumentos: 
        return

    destinatario, conteudo = argumentos.split(b' :', 1)
    msg = b':' + remetente + b' PRIVMSG ' + destinatario + b' :' + conteudo + b'\r\n'
    
    if destinatario.startswith(b'#'):
        canal_lwr = destinatario.lower()
        if canal_lwr in grupos_de_canais and conexao in grupos_de_canais[canal_lwr]:
            for membro in grupos_de_canais[canal_lwr]:
                if membro != conexao:
                    membro.enviar(msg)
    else:
        conexao_destino = encontrar_conexao_por_apelido(destinatario)
        if conexao_destino:
            conexao_destino.enviar(msg)

def handle_join(conexao, argumentos):
    if 'apelido' not in mapa_conexoes_usuario[conexao]:
        return
        
    remetente = mapa_conexoes_usuario[conexao]['apelido']
    nome_do_canal = argumentos.split(b' ')[0]

    if not nome_do_canal.startswith(b'#') or not validar_nome_de_recurso(nome_do_canal[1:]):
        conexao.enviar(b':server 403 ' + nome_do_canal + b' :No such channel\r\n')
        return
        
    canal_lwr = nome_do_canal.lower()
        
    if canal_lwr not in grupos_de_canais:
        grupos_de_canais[canal_lwr] = []
    
    if conexao in grupos_de_canais[canal_lwr]:
        return
    
    grupos_de_canais[canal_lwr].append(conexao)
    
    msg_join = b':' + remetente + b' JOIN :' + nome_do_canal + b'\r\n'
    for membro in grupos_de_canais[canal_lwr]:
        membro.enviar(msg_join)
    
    membros_atuais = sorted([
        mapa_conexoes_usuario[c]['apelido'] 
        for c in grupos_de_canais[canal_lwr] 
        if c in mapa_conexoes_usuario and 'apelido' in mapa_conexoes_usuario[c]
    ])
    
    prefixo = b':server 353 ' + remetente + b' = ' + nome_do_canal + b' :'
    tamanho_prefixo = len(prefixo)
    tamanho_sufixo = 2
    limite = 512 - tamanho_prefixo - tamanho_sufixo
    
    lista_atual = []
    tamanho_atual = 0
    
    for membro in membros_atuais:
        tamanho_membro = len(membro) + 1
        if tamanho_atual + tamanho_membro > limite and lista_atual:
            conexao.enviar(prefixo + b' '.join(lista_atual) + b'\r\n')
            lista_atual = []
            tamanho_atual = 0
        
        lista_atual.append(membro)
        tamanho_atual += tamanho_membro
    
    if lista_atual:
        conexao.enviar(prefixo + b' '.join(lista_atual) + b'\r\n')
    
    conexao.enviar(b':server 366 ' + remetente + b' ' + nome_do_canal + b' :End of /NAMES list.\r\n')

def handle_part(conexao, argumentos):
    remetente = mapa_conexoes_usuario[conexao]['apelido']
    nome_do_canal = argumentos.split(b' ')[0]
    canal_lwr = nome_do_canal.lower()
        
    if canal_lwr in grupos_de_canais and conexao in grupos_de_canais[canal_lwr]:
        membros = grupos_de_canais[canal_lwr]
        msg_part = b':' + remetente + b' PART ' + nome_do_canal + b'\r\n'
        
        for membro in membros:
            membro.enviar(msg_part)
            
        membros.remove(conexao)
        if not membros:
            del grupos_de_canais[canal_lwr]

## ============================================================================
## Integração com as demais camadas
## ============================================================================

nossa_ponta = '192.168.200.4'
outra_ponta = '192.168.200.3'
porta_tcp = 7000

driver = ZyboSerialDriver()
linha_serial = driver.obter_porta(0)

enlace = CamadaEnlace({outra_ponta: linha_serial})

rede = IP(enlace)
rede.definir_endereco_host(nossa_ponta)
rede.definir_tabela_encaminhamento([
    ('0.0.0.0/0', outra_ponta)
])

servidor = Servidor(rede, porta_tcp)
servidor.registrar_monitor_de_conexoes_aceitas(conexao_aceita)

print('=' * 70)
print('🚀 PLACA 3 - Servidor IRC')
print('=' * 70)
print(f'Endereço: {nossa_ponta}:{porta_tcp}')
print('Aguardando conexões...')
print('=' * 70)

asyncio.get_event_loop().run_forever()