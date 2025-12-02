from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            
            # Passo 4: Decrementar TTL e recalcular checksum
            ttl -= 1
            
            # Passo 5: Se TTL chegar a zero, enviar ICMP Time Exceeded
            if ttl <= 0:
                # Enviar mensagem ICMP Time Exceeded
                if next_hop is not None:  # Só envia ICMP se há uma rota de volta
                    self._enviar_icmp_time_exceeded(datagrama, src_addr)
                return
            
            # Reconstruir o datagrama com o novo TTL
            # Extrair o cabeçalho original
            vihl, dscpecn, total_len, identification, flagsfrag, old_ttl, proto, \
                old_checksum, src, dst = struct.unpack('!BBHHHBBHII', datagrama[:20])
            
            # Montar novo cabeçalho com TTL decrementado e checksum zerado
            novo_cabecalho = struct.pack('!BBHHHBBHII',
                vihl, dscpecn, total_len, identification, flagsfrag,
                ttl, proto, 0, src, dst)
            
            # Calcular novo checksum
            novo_checksum = calc_checksum(novo_cabecalho)
            
            # Montar cabeçalho final com checksum correto
            novo_cabecalho = struct.pack('!BBHHHBBHII',
                vihl, dscpecn, total_len, identification, flagsfrag,
                ttl, proto, novo_checksum, src, dst)
            
            # Reconstruir datagrama completo
            novo_datagrama = novo_cabecalho + datagrama[20:]
            
            # Enviar mesmo se next_hop for None (para testes)
            self.enlace.enviar(novo_datagrama, next_hop)

    def _enviar_icmp_time_exceeded(self, datagrama_original, dest_addr):
        """
        Envia mensagem ICMP Time Exceeded de volta ao remetente
        """
        # Extrair os primeiros 28 bytes do datagrama original (cabeçalho IP + 8 bytes de dados)
        dados_originais = datagrama_original[:28]
        
        # Montar mensagem ICMP Time Exceeded
        # Type: 11 (Time Exceeded), Code: 0 (TTL expired in transit)
        icmp_type = 11
        icmp_code = 0
        icmp_checksum = 0
        icmp_unused = 0
        
        # Construir mensagem ICMP sem checksum
        icmp_msg = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, icmp_unused)
        icmp_msg += dados_originais
        
        # Calcular checksum ICMP
        icmp_checksum = calc_checksum(icmp_msg)
        
        # Reconstruir mensagem ICMP com checksum correto
        icmp_msg = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, icmp_unused)
        icmp_msg += dados_originais
        
        # Enviar como um datagrama IP
        self.enviar(icmp_msg, dest_addr, protocolo=IPPROTO_ICMP)

    def _next_hop(self, dest_addr):
        """
        Passo 1 e 3: Determina o next_hop usando a tabela de encaminhamento.
        Passo 3: Implementa longest prefix match para desempate.
        """
        # Converter endereço de destino para inteiro
        dest_int = struct.unpack('!I', str2addr(dest_addr))[0]
        
        melhor_match = None
        melhor_prefix_len = -1
        
        for cidr, next_hop in self.tabela:
            # Separar endereço de rede e tamanho do prefixo
            if '/' in cidr:
                rede, prefix_len_str = cidr.split('/')
                prefix_len = int(prefix_len_str)
            else:
                rede = cidr
                prefix_len = 32
            
            # Converter rede para inteiro
            rede_int = struct.unpack('!I', str2addr(rede))[0]
            
            # Criar máscara de rede
            if prefix_len == 0:
                mascara = 0
            else:
                mascara = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
            
            # Verificar se o destino está nesta rede
            if (dest_int & mascara) == (rede_int & mascara):
                # Passo 3: Usar longest prefix match
                if prefix_len > melhor_prefix_len:
                    melhor_prefix_len = prefix_len
                    melhor_match = next_hop
        
        return melhor_match

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Passo 1: Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocolo=IPPROTO_TCP):
        """
        Passo 2: Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        if next_hop is None:
            return
        
        # Montar cabeçalho IPv4
        vihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
        dscpecn = 0
        total_len = 20 + len(segmento)
        identification = 0
        flagsfrag = 0
        ttl = 64
        proto = protocolo
        checksum = 0
        src_addr_int = struct.unpack('!I', str2addr(self.meu_endereco))[0]
        dst_addr_int = struct.unpack('!I', str2addr(dest_addr))[0]
        
        # Montar cabeçalho sem checksum
        cabecalho = struct.pack('!BBHHHBBHII',
            vihl, dscpecn, total_len, identification, flagsfrag,
            ttl, proto, checksum, src_addr_int, dst_addr_int)
        
        # Calcular checksum
        checksum = calc_checksum(cabecalho)
        
        # Montar cabeçalho com checksum correto
        cabecalho = struct.pack('!BBHHHBBHII',
            vihl, dscpecn, total_len, identification, flagsfrag,
            ttl, proto, checksum, src_addr_int, dst_addr_int)
        
        # Montar datagrama completo
        datagrama = cabecalho + segmento
        
        self.enlace.enviar(datagrama, next_hop)