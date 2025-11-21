import time
from typing import List, Dict, Any


def print_header(title, width=60):
    """Imprimir cabeçalho bonito"""
    print("\n" + "="*width)
    print(f"{title:^{width}}")
    print("="*width)


def print_box(title, lines, width=60):
    """Imprimir caixa com título e linhas"""
    print("\n╔" + "═"*(width-2) + "╗")
    print(f"║ {title:^{width-4}} ║")
    print("╠" + "═"*(width-2) + "╣")
    for line in lines:
        print(f"║ {line:<{width-4}} ║")
    print("╚" + "═"*(width-2) + "╝")


def print_menu(title, options, width=60):
    """
    Imprimir menu com opções numeradas
    
    Args:
        title: Título do menu
        options: Lista de strings com opções
        width: Largura da caixa
    """
    print("\n╔" + "═"*(width-2) + "╗")
    print(f"║ {title:^{width-4}} ║")
    print("╠" + "═"*(width-2) + "╣")
    
    for i, option in enumerate(options, 1):
        print(f"║ {i}. {option:<{width-7}} ║")
    
    print("╚" + "═"*(width-2) + "╝")


def print_success(message):
    """Imprimir mensagem de sucesso"""
    print(f"✅ {message}")


def print_error(message):
    """Imprimir mensagem de erro"""
    print(f"❌ {message}")


def print_warning(message):
    """Imprimir mensagem de aviso"""
    print(f"⚠️  {message}")


def print_info(message):
    """Imprimir mensagem informativa"""
    print(f"ℹ️  {message}")


def print_auction_details(auction, status=None):
    """
    Imprimir detalhes de um leilão de forma formatada
    
    Args:
        auction: Objeto AuctionAnnouncement
        status: Status do leilão (opcional)
    """
    print("\n" + "-"*60)
    print(f"🏛️  Auction ID: {auction.auction_id}")
    print(f"📦 Item: {auction.item_description}")
    print(f"⏰ Start: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(auction.start_time))}")
    print(f"⏰ End: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(auction.end_time))}")
    if status:
        print(f"📊 Status: {status.value}")
    print("-"*60)


def print_bid_details(bid):
    """
    Imprimir detalhes de uma bid de forma formatada
    
    Args:
        bid: Objeto Bid
    """
    print(f"  💰 Bid ID: {bid.bid_id}")
    print(f"     Amount: {bid.bid_value:.2f}€")
    print(f"     Time: {time.strftime('%H:%M:%S', time.localtime(bid.timestamp))}")


def print_table(headers: List[str], rows: List[List[Any]], widths: List[int] = None):
    """
    Imprimir tabela formatada
    
    Args:
        headers: Lista de cabeçalhos
        rows: Lista de linhas (cada linha é uma lista de valores)
        widths: Lista de larguras das colunas (opcional)
    """
    if not widths:
        widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 for i in range(len(headers))]
    
    # Linha superior
    print("\n┌" + "┬".join("─"*w for w in widths) + "┐")
    
    # Cabeçalhos
    print("│" + "│".join(f"{headers[i]:^{widths[i]}}" for i in range(len(headers))) + "│")
    
    # Linha separadora
    print("├" + "┼".join("─"*w for w in widths) + "┤")
    
    # Linhas de dados
    for row in rows:
        print("│" + "│".join(f"{str(row[i]):<{widths[i]}}" for i in range(len(row))) + "│")
    
    # Linha inferior
    print("└" + "┴".join("─"*w for w in widths) + "┘")


def get_input(prompt, input_type=str, validator=None):
    """
    Obter input do utilizador com validação
    
    Args:
        prompt: Mensagem a mostrar
        input_type: Tipo esperado (str, int, float)
        validator: Função de validação opcional
        
    Returns:
        Valor validado
    """
    while True:
        try:
            value = input(f"➤ {prompt}: ")
            
            # Converter para tipo correto
            if input_type != str:
                value = input_type(value)
            
            # Validar se fornecido validador
            if validator and not validator(value):
                print_error("Valor inválido, tenta novamente")
                continue
            
            return value
            
        except ValueError:
            print_error(f"Por favor insere um {input_type.__name__} válido")
        except KeyboardInterrupt:
            print("\n")
            raise


def get_confirmation(prompt):
    """
    Obter confirmação sim/não
    
    Args:
        prompt: Mensagem a mostrar
        
    Returns:
        bool: True se sim, False se não
    """
    while True:
        response = input(f"➤ {prompt} (s/n): ").lower().strip()
        if response in ['s', 'sim', 'y', 'yes']:
            return True
        elif response in ['n', 'nao', 'não', 'no']:
            return False
        else:
            print_error("Por favor responde 's' ou 'n'")


def print_progress(message, duration=2):
    """
    Mostrar mensagem de progresso com animação
    
    Args:
        message: Mensagem a mostrar
        duration: Duração em segundos
    """
    import sys
    
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r{frames[i % len(frames)]} {message}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write(f"\r✅ {message} - Concluído!\n")
    sys.stdout.flush()


def clear_screen():
    """Limpar o ecrã"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def press_enter_to_continue():
    """Esperar que o utilizador pressione Enter"""
    input("\n[Pressiona Enter para continuar...]")


def print_node_status(node):
    """
    Imprimir status do node de forma bonita
    
    Args:
        node: Objeto AuctionNode
    """
    lines = [
        f"👤 User: {node.username}",
        f"🔗 Peers conectados: {len(node.peer_sockets)}",
        f"⛓️  Blocos na chain: {len(node.blockchain.chain)}",
        f"📋 Transações pendentes: {len(node.blockchain.pending_transactions)}",
        f"🏛️  Leilões ativos: {len(node.auction_manager.get_active_auctions())}",
    ]
    
    print_box("STATUS DO NODE", lines)


def format_timestamp(timestamp):
    """Formatar timestamp para string legível"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


def format_currency(amount):
    """Formatar valor monetário"""
    return f"{amount:.2f}€"


def print_logo():
    """Imprimir logo ASCII do sistema"""
    logo = """
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║        🏛️  SISTEMA DE LEILÃO P2P  🏛️              ║
    ║                                                   ║
    ║        Privacy-Preserving Auction System         ║
    ║        Com Ring Signatures & Blockchain          ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(logo)


def print_divider(char="─", width=60):
    """Imprimir linha divisória"""
    print(char * width)


# ========== TESTE ==========
if __name__ == '__main__':
    # Testar todas as funções
    print_logo()
    
    print_header("Teste de UI", 50)
    
    print_success("Operação bem sucedida!")
    print_error("Algo correu mal!")
    print_warning("Atenção a isto!")
    print_info("Informação útil")
    
    print_menu("Menu Principal", [
        "📢 Criar Leilão",
        "💰 Fazer Bid",
        "📋 Ver Leilões",
        "❌ Sair"
    ])
    
    print_box("Informações", [
        "Nome: Alice",
        "Peers: 3",
        "Blocos: 42"
    ])
    
    print_table(
        ["ID", "Item", "Status"],
        [
            ["abc123", "Laptop", "ACTIVE"],
            ["def456", "Mouse", "COMPLETED"]
        ]
    )
    
    print("\n✨ Todos os componentes UI testados!")