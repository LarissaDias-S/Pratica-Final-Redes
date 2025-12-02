import asyncio
import random
import time
from tcputils import (
    FLAGS_SYN, FLAGS_ACK, FLAGS_FIN, MSS,
    read_header, calc_checksum, fix_checksum, make_header
)

DEBUG = True

def debug_print(msg):
    if DEBUG:
        print(f"[TCP] {msg}")

def make_segment(src_addr, dst_addr, src_port, dst_port, seq_no, ack_no, flags, payload=b''):
    header = make_header(src_port, dst_port, seq_no, ack_no, flags)
    return fix_checksum(header + payload, src_addr, dst_addr)

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)
        debug_print(f"Servidor iniciado na porta {porta}")

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        debug_print(f"Segmento recebido de {src_addr}")
        src_port, dst_port, seq_no, ack_no, flags, window_size, checksum, urg_ptr = read_header(segment)
        
        if dst_port != self.porta:
            debug_print(f"Porta errada: {dst_port} != {self.porta}")
            return
            
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            debug_print("Checksum inválido!")
            return
            
        data_offset_words = (segment[12] >> 4) & 0xF
        payload = segment[4 * data_offset_words:]
        conn_id = (src_addr, src_port, dst_addr, dst_port)

        if flags & FLAGS_SYN:
            debug_print(f"SYN recebido! Criando conexão...")
            esperado_cli = seq_no + 1
            meu_isn = random.randint(0, 0xFFFFFFFF)
            con = self.conexoes[conn_id] = Conexao(self, conn_id, meu_isn, esperado_cli)
            syn_ack = make_segment(dst_addr, src_addr, dst_port, src_port, meu_isn, esperado_cli, FLAGS_SYN | FLAGS_ACK)
            self.rede.enviar(syn_ack, src_addr)
            debug_print(f"SYN-ACK enviado!")
            if self.callback:
                self.callback(con)
            return

        if conn_id in self.conexoes:
            self.conexoes[conn_id]._rdt_rcv(seq_no, ack_no, flags, payload)

class Conexao:
    def __init__(self, servidor, id_conexao, nosso_isn, prox_esperado_cli):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.estado = 'SYN_RCVD'
        self.seq_no_esperado = prox_esperado_cli
        self.seq_no_a_enviar = (nosso_isn + 1) & 0xFFFFFFFF
        self.prox_seq_no_nao_ack = self.seq_no_a_enviar
        self.buffer_de_envio = []
        self.dados_pendentes = b''
        self.estimated_rtt = None
        self.dev_rtt = None
        self.timeout_interval = 1.0
        self._timer_task = None
        self.cwnd = MSS
        self.bytes_ack_acum = 0
        self.timer_ativo = False

    def _start_timer(self):
        if not self.timer_ativo and self.buffer_de_envio:
            self.timer_ativo = True
            try:
                loop = asyncio.get_running_loop()
                self._timer_task = loop.create_task(self._timer_coroutine())
            except RuntimeError:
                self.timer_ativo = False

    def _stop_timer(self):
        if self._timer_task and not self._timer_task.done():
            self._timer_task.cancel()
        self._timer_task = None
        self.timer_ativo = False

    async def _timer_coroutine(self):
        try:
            await asyncio.sleep(self.timeout_interval)
            self._timeout()
        except asyncio.CancelledError:
            raise

    def _timeout(self):
        self.timer_ativo = False
        if self.buffer_de_envio:
            self.cwnd = max(MSS, self.cwnd // 2)
            self.bytes_ack_acum = 0
            
            seg0 = self.buffer_de_envio[0]
            cli_ip, cli_port, srv_ip, srv_port = self.id_conexao
            payload = seg0["seg"][20:]
            retx = make_segment(srv_ip, cli_ip, srv_port, cli_port, 
                               seg0["seq"], self.seq_no_esperado, FLAGS_ACK, payload)
            
            seg0["seg"] = retx
            seg0["t"] = time.time()
            seg0["rtt"] = False
            
            self.servidor.rede.enviar(retx, cli_ip)
            self._start_timer()

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        debug_print(f"Conexao._rdt_rcv: estado={self.estado}, flags={flags}, payload_len={len(payload)}")
        
        if self.estado == 'SYN_RCVD' and (flags & FLAGS_ACK) and ack_no == self.seq_no_a_enviar:
            self.estado = 'ESTABLISHED'
            debug_print("Conexão ESTABLISHED!")

        if flags & FLAGS_ACK and ack_no > self.prox_seq_no_nao_ack:
            now = time.time()
            for item in self.buffer_de_envio:
                if item["rtt"] and item["seq"] + item["len"] <= ack_no:
                    sample_rtt = now - item["t"]
                    self._atualiza_rtt(sample_rtt)
                    break
            
            self._stop_timer()
            
            bytes_acked = 0
            while self.buffer_de_envio and self.buffer_de_envio[0]["seq"] + self.buffer_de_envio[0]["len"] <= ack_no:
                bytes_acked += self.buffer_de_envio.pop(0)["len"]
            
            self.prox_seq_no_nao_ack = ack_no
            
            if bytes_acked:
                self.bytes_ack_acum += bytes_acked
                while self.bytes_ack_acum >= self.cwnd:
                    self.cwnd += MSS
                    self.bytes_ack_acum -= (self.cwnd - MSS)
            
            self._try_send_from_pending()
            
            if self.buffer_de_envio:
                self._start_timer()

        if self.estado in ('ESTABLISHED', 'SYN_RCVD'):
            enviar_ack = False
            if seq_no == self.seq_no_esperado:
                if payload:
                    debug_print(f"Recebido {len(payload)} bytes: {payload[:50]}")
                    if self.callback:
                        self.callback(self, payload)
                    self.seq_no_esperado += len(payload)
                    enviar_ack = True
                if flags & FLAGS_FIN:
                    debug_print("FIN recebido")
                    self.seq_no_esperado += 1
                    if self.callback:
                        self.callback(self, b'')
                    self.estado = 'CLOSE_WAIT'
                    enviar_ack = True
            else:
                enviar_ack = True
            
            if enviar_ack:
                cli_ip, cli_port, srv_ip, srv_port = self.id_conexao
                ack_seg = make_segment(srv_ip, cli_ip, srv_port, cli_port, 
                                      self.seq_no_a_enviar, self.seq_no_esperado, FLAGS_ACK)
                self.servidor.rede.enviar(ack_seg, cli_ip)
                debug_print("ACK enviado")

    def _atualiza_rtt(self, sample_rtt: float):
        alpha, beta = 0.125, 0.25
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2.0
        else:
            self.estimated_rtt = (1 - alpha) * self.estimated_rtt + alpha * sample_rtt
            self.dev_rtt = (1 - beta) * self.dev_rtt + beta * abs(sample_rtt - self.estimated_rtt)
        
        rto = self.estimated_rtt + 4 * self.dev_rtt
        self.timeout_interval = max(0.2, min(0.3, rto))

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados: bytes):
        if dados:
            self.dados_pendentes += dados
            debug_print(f"Dados adicionados ao buffer: {len(dados)} bytes, total pendente: {len(self.dados_pendentes)}")
        
        if not self.dados_pendentes:
            debug_print("Nada para enviar")
            return
        
        cli_ip, cli_port, srv_ip, srv_port = self.id_conexao
        bytes_em_voo = (self.seq_no_a_enviar - self.prox_seq_no_nao_ack) & 0xFFFFFFFF
        espaco_disponivel = max(0, self.cwnd - bytes_em_voo)
        
        debug_print(f"cwnd={self.cwnd}, bytes_em_voo={bytes_em_voo}, espaco={espaco_disponivel}")
        
        if espaco_disponivel == 0:
            debug_print("Janela cheia, aguardando ACK")
            return
        
        enviados = 0
        
        # Enviar segmentos enquanto houver dados e espaço
        while self.dados_pendentes and espaco_disponivel > 0:
            # Tamanho do próximo segmento: MSS ou o que sobrou (o menor)
            tamanho_seg = min(MSS, len(self.dados_pendentes), espaco_disponivel)
            payload = self.dados_pendentes[:tamanho_seg]
            
            seg = make_segment(srv_ip, cli_ip, srv_port, cli_port, 
                            self.seq_no_a_enviar, self.seq_no_esperado, FLAGS_ACK, payload)
            
            eh_primeiro = len(self.buffer_de_envio) == 0
            
            self.buffer_de_envio.append({
                "seq": self.seq_no_a_enviar,
                "seg": seg,
                "len": tamanho_seg,
                "t": time.time(),
                "rtt": eh_primeiro
            })
            
            self.servidor.rede.enviar(seg, cli_ip)
            debug_print(f"✅ Segmento ENVIADO: seq={self.seq_no_a_enviar}, len={tamanho_seg}")
            
            self.seq_no_a_enviar = (self.seq_no_a_enviar + tamanho_seg) & 0xFFFFFFFF
            self.dados_pendentes = self.dados_pendentes[tamanho_seg:]
            espaco_disponivel -= tamanho_seg
            enviados += 1
            
            if eh_primeiro:
                self._start_timer()
        
        debug_print(f"Total de segmentos enviados: {enviados}, restam {len(self.dados_pendentes)} bytes pendentes")

    def _try_send_from_pending(self):
        if self.dados_pendentes:
            self.enviar(b'')

    def fechar(self):
        if self.estado in ('CLOSE_WAIT', 'ESTABLISHED'):
            debug_print("Fechando conexão")
            cli_ip, cli_port, srv_ip, srv_port = self.id_conexao
            fin = make_segment(srv_ip, cli_ip, srv_port, cli_port, 
                             self.seq_no_a_enviar, self.seq_no_esperado, FLAGS_FIN | FLAGS_ACK)
            self.seq_no_a_enviar = (self.seq_no_a_enviar + 1) & 0xFFFFFFFF
            self.estado = 'LAST_ACK'
            self.servidor.rede.enviar(fin, cli_ip)