class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    # Constantes SLIP conforme RFC 1055
    END = b'\xc0'    # Delimitador de quadro
    ESC = b'\xdb'    # Escape
    ESC_END = b'\xdc' # Sequência de escape para o byte 0xC0
    ESC_ESC = b'\xdd' # Sequência de escape para o byte 0xDB
    
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.callback = None
        self.buffer = bytearray()  # Buffer para armazenar dados brutos recebidos
        self.datagrama = bytearray() # Buffer para o datagrama que está sendo decodificado
        self.escapando = False  # Flag para indicar que o byte anterior foi 0xDB

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        """
        Passo 1 & 2: Delimita o quadro com 0xC0 e aplica sequências de escape.
        """
        quadro = bytearray()
        quadro.extend(self.END)  # Delimitador inicial (0xC0)
        
        for byte in datagrama:
            if byte == 0xC0:
                # Escapa 0xC0 com 0xDB 0xDC
                quadro.extend(self.ESC)
                quadro.extend(self.ESC_END)
            elif byte == 0xDB:
                # Escapa 0xDB com 0xDB 0xDD
                quadro.extend(self.ESC)
                quadro.extend(self.ESC_ESC)
            else:
                quadro.append(byte)
                
        quadro.extend(self.END)  # Delimitador final (0xC0)
        self.linha_serial.enviar(bytes(quadro))

    def __raw_recv(self, dados):
        """
        Passo 3, 4 & 5: Recebe e processa quadros SLIP, tratando escapes e quadros quebrados.
        """
        self.buffer.extend(dados)  # Adiciona dados recebidos ao buffer
        
        i = 0
        while i < len(self.buffer):
            byte = self.buffer[i]
            
            # --- Lógica de Decodificação e Escape (Passo 4) ---
            if self.escapando:
                self.escapando = False
                
                if byte == 0xDC:  # ESC_END (0xDC) -> Decodifica para 0xC0
                    self.datagrama.append(0xC0)
                elif byte == 0xDD:  # ESC_ESC (0xDD) -> Decodifica para 0xDB
                    self.datagrama.append(0xDB)
                
                i += 1
                continue
            
            # --- Lógica de Controle (0xDB e 0xC0) ---
            if byte == 0xDB:
                # Início de uma sequência de escape (ESC)
                self.escapando = True
                i += 1
                continue
            
            if byte == 0xC0:
                # Delimitador de quadro (END)
                
                # Passo 5: Limpeza do datagrama em caso de erro na camada superior
                if self.datagrama:  # Descarta datagramas vazios (Passo 3)
                    try:
                        if self.callback:
                            self.callback(bytes(self.datagrama))
                    except:
                        # Ignora a exceção, mas mostra na tela
                        import traceback
                        traceback.print_exc()
                    finally:
                        # Limpa o datagrama
                        self.datagrama = bytearray()
                else:
                    # Datagrama vazio
                    self.datagrama = bytearray()
                
                self.escapando = False # Limpa o estado de escape
                i += 1
                continue
            
            # --- Lógica de Dados Normais ---
            # Byte normal (não é escape nem delimitador)
            self.datagrama.append(byte)
            i += 1
        
        # --- Lógica de Limpeza do Buffer Bruto (Passo 3) ---
        # Remove do buffer todos os bytes que foram processados.
        self.buffer = self.buffer[i:]