from iputils import *
from struct import pack


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

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dest_addr, payload = read_ipv4_header(datagrama)   
        
        ttl -= 1
        
        # Se o ttl for diferente de zero
        if ttl:
            datagrama = (
                pack(
                "!BBHHHBBH", 0x45, dscp & ecn, len(payload), 
                identification, flags & frag_offset, ttl, proto, 0
                ) 
                + str2addr(src_addr) + str2addr(dest_addr))
            datagrama = datagrama[:10] + pack('!H', calc_checksum(datagrama)) + datagrama[12:]   

        # Se o ttl for zero
        else:
            # Cria um datagrama de tempo de vida esgotado
            datagrama = pack("!BBHI", 0x0b, 0x00, 0, 0) + datagrama[:28]
            datagrama = datagrama[:2] + pack('!H', calc_checksum(datagrama)) + datagrama[4:]
            self.enviar(datagrama, src_addr, 0x01)
            return
        if dest_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dest_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dest_addr)
            self.enlace.enviar(datagrama, next_hop)


    def _next_hop(self, dest_addr):
        rotas_compativeis = []
        for cidr, next_hop in self.tabela_encaminhamento:
            ip, prefixo = cidr.split('/')
            prefixo = int(prefixo)
            # Divide o endereço de destino em partes (octetos).
            dst_addr_partes = [int(part) for part in dest_addr.split('.')]
            ip_partes = [int(part) for part in ip.split('.')]

            # Calcula a máscara com base no prefixo.
            mascara = (1 << 32) - (1 << (32 - prefixo))

            # Converte endereços em formato de lista em valores inteiros.
            ip_int = sum(bit << (24 - 8 * i) for i, bit in enumerate(dst_addr_partes))
            rede_int = sum(bit << (24 - 8 * i) for i, bit in enumerate(ip_partes))

            # Verifica se o endereço de destino pertence à rede com base na máscara.
            if (ip_int & mascara) == (rede_int & mascara):
                rotas_compativeis.append((prefixo, next_hop))
                
        if rotas_compativeis:
            # Ordena e retorna a entrada com o prefixo mais longo,
            # quando o endereço IP de destino casar com mais de um CIDR da tabela.
            rotas_compativeis.sort(reverse=True)
            return rotas_compativeis[0][1]


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, proto = 0x06):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        # Datagrama com checksum 0
        datagrama = (
            pack(
            '!BBHHHBBH', 
            0x45, # versão do protocolo ip e tamanho do cabeçalho
            0, # DSCP e ECN
            20 + len(segmento), # comprimento do datagrama 
            0, # identificador
            0, # flags e offset 
            64, # ttl(tempo de vida)
            proto, # ICMP ou TCP
            0 # checksum
            )
            + str2addr(self.meu_endereco) # endereço de origem
            + str2addr(dest_addr) # endereço de destino
            )

        # Datagrama com checksum calculado
        datagrama = datagrama[:10] + pack('!H', calc_checksum(datagrama)) + \
                    datagrama[12:] + segmento

        next_hop = self._next_hop(dest_addr)
        self.enlace.enviar(datagrama, next_hop)
