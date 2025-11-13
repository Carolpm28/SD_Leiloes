// ==================== CONFIGURAÇÃO ====================

// URL base da API - muda isto dependendo do cliente
const API_BASE_URL = 'http://localhost:5002';

// ==================== NAVEGAÇÃO ====================

document.addEventListener('DOMContentLoaded', function() {
    // Inicializar sistema
    initializeApp();
    
    // Configurar navegação
    setupNavigation();
    
    // Configurar formulários
    setupForms();
    
    // Carregar dados iniciais
    loadInitialData();
});

function initializeApp() {
    console.log('Inicializando aplicação...');
    
    // Verificar conexão com API
    checkAPIConnection();
    setupFilters();
    // Configurar auto-refresh
    setInterval(refreshAuctions, 30000); // Atualiza a cada 30 segundos
}

async function checkAPIConnection() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/info`);
        const info = await response.json();
        console.log('Conectado ao backend:', info);
    } catch (error) {
        console.error('Erro ao conectar ao backend:', error);
        showNotification('Erro ao conectar ao servidor!', 'error');
    }
}

function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const pageToShow = this.getAttribute('data-page');
            navigateTo(pageToShow);
        });
    });
}

function navigateTo(pageName) {
    // Esconder todas as páginas
    const allPages = document.querySelectorAll('.page-section');
    allPages.forEach(page => page.classList.remove('active'));
    
    // Mostrar página selecionada
    const selectedPage = document.getElementById(`page-${pageName}`);
    if (selectedPage) {
        selectedPage.classList.add('active');
    }
    
    // Atualizar nav link ativo
    const allNavLinks = document.querySelectorAll('.nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === pageName) {
            link.classList.add('active');
        }
    });
    
    // Carregar dados da página
    loadPageData(pageName);
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function loadPageData(pageName) {
    switch(pageName) {
        case 'leiloes':
            await loadActiveAuctions();
            break;
        case 'meus-leiloes':
            await loadMyAuctions();
            break;
        case 'minhas-licitacoes':
            await loadMyBids();
            break;
    }
}

// ==================== CARREGAR DADOS INICIAIS ====================

async function loadInitialData() {
    await loadActiveAuctions();
}

async function refreshAuctions() {
    const currentPage = document.querySelector('.page-section.active');
    if (currentPage && currentPage.id === 'page-leiloes') {
        await loadActiveAuctions();
    }
}

// ==================== LEILÕES ATIVOS ====================

async function loadActiveAuctions() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/active`);
        const auctions = await response.json();
        
        console.log('📥 Leilões ativos carregados:', auctions.length);
        
        const grid = document.querySelector('#page-leiloes .auctions-grid');
        
        if (auctions.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <h3>Nenhum leilão ativo no momento</h3>
                    <p>Seja o primeiro a criar um leilão!</p>
                    <button class="btn-primary" onclick="navigateTo('criar')">CRIAR LEILÃO</button>
                </div>
            `;
            return;
        }
        
        grid.innerHTML = auctions.map(auction => createAuctionCard(auction)).join('');
        
    } catch (error) {
        console.error('Erro ao carregar leilões:', error);
        showNotification('Erro ao carregar leilões!', 'error');
    }
}

function createAuctionCard(auction) {
    const closingDate = new Date(auction.closing_date);
    const now = new Date();
    const timeLeft = closingDate - now;
    const daysLeft = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
    const hoursLeft = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    
    const minBidText = auction.min_bid ? `€${auction.min_bid.toFixed(2)}` : 'Sem mínimo';
    
    return `
        <div class="auction-card" data-auction-id="${auction.auction_id}">
            <div class="auction-image">
                <img src="https://via.placeholder.com/400x300?text=${encodeURIComponent(auction.item)}" 
                     alt="${auction.item}">
                <div class="auction-badge">Ativo</div>
            </div>
            <div class="auction-content">
                <h3 class="auction-title">${auction.item}</h3>
                <div class="auction-info">
                    <div class="info-item">
                        <span class="info-label">Preço Mínimo:</span>
                        <span class="info-value">${minBidText}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Termina em:</span>
                        <span class="info-value">${daysLeft}d ${hoursLeft}h</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Data de Encerramento:</span>
                        <span class="info-value">${closingDate.toLocaleString('pt-PT')}</span>
                    </div>
                </div>
                <button class="btn-primary btn-full" onclick="showBidModal('${auction.auction_id}', '${auction.item}', ${auction.min_bid || 0})">
                    VER DETALHES E LICITAR
                </button>
            </div>
        </div>
    `;
}

// ==================== MEUS LEILÕES ====================

async function loadMyAuctions() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/mine`);
        const auctions = await response.json();
        
        console.log('Meus leilões carregados:', auctions.length);
        
        const grid = document.querySelector('#page-meus-leiloes .auctions-grid');
        
        if (auctions.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <h3>Ainda não criou nenhum leilão</h3>
                    <p>Crie o seu primeiro leilão e comece a vender!</p>
                    <button class="btn-primary" onclick="navigateTo('criar')">CRIAR LEILÃO</button>
                </div>
            `;
            return;
        }
        
        grid.innerHTML = auctions.map(auction => createMyAuctionCard(auction)).join('');
        
    } catch (error) {
        console.error('Erro ao carregar meus leilões:', error);
        showNotification('Erro ao carregar seus leilões!', 'error');
    }
}

function createMyAuctionCard(auction) {
    const closingDate = new Date(auction.closing_date);
    
    return `
        <div class="auction-card my-auction" data-auction-id="${auction.auction_id}">
            <div class="auction-image">
                <img src="https://via.placeholder.com/400x300?text=${encodeURIComponent(auction.item)}" 
                     alt="${auction.item}">
                <div class="auction-badge auction-badge-mine">Meu Leilão</div>
            </div>
            <div class="auction-content">
                <h3 class="auction-title">${auction.item}</h3>
                <div class="auction-info">
                    <div class="info-item">
                        <span class="info-label">Preço Mínimo:</span>
                        <span class="info-value">€${auction.min_bid ? auction.min_bid.toFixed(2) : '0.00'}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Encerra em:</span>
                        <span class="info-value">${closingDate.toLocaleString('pt-PT')}</span>
                    </div>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button class="btn-primary" onclick="viewAuctionBids('${auction.auction_id}')">
                        VER LICITAÇÕES
                    </button>
                    <button class="btn-secondary" onclick="viewWinner('${auction.auction_id}')">
                        VER VENCEDOR
                    </button>
                </div>
            </div>
        </div>
    `;
}

async function viewAuctionBids(auctionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/${auctionId}/bids`);
        const bids = await response.json();
        
        if (bids.length === 0) {
            alert('Ainda não há licitações neste leilão.');
            return;
        }
        
        const bidsText = bids.map((bid, index) => 
            `${index + 1}. €${bid.value.toFixed(2)} - ${new Date(bid.timestamp).toLocaleString('pt-PT')}`
        ).join('\n');
        
        alert(`Licitações recebidas (${bids.length}):\n\n${bidsText}`);
        
    } catch (error) {
        console.error('Erro ao carregar licitações:', error);
        showNotification('Erro ao carregar licitações!', 'error');
    }
}

async function viewWinner(auctionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/${auctionId}/winner`);
        
        if (response.status === 404) {
            alert('Ainda não há licitações neste leilão.');
            return;
        }
        
        const winner = await response.json();
        alert(`🏆 VENCEDOR ATUAL:\n\nValor: €${winner.value.toFixed(2)}\nData: ${new Date(winner.timestamp).toLocaleString('pt-PT')}`);
        
    } catch (error) {
        console.error('Erro ao carregar vencedor:', error);
        showNotification('Erro ao carregar vencedor!', 'error');
    }
}

// ==================== MINHAS LICITAÇÕES ====================

async function loadMyBids() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/bids/mine`);
        const bids = await response.json();
        
        console.log('Minhas licitações carregadas:', bids.length);
        
        const grid = document.querySelector('#page-minhas-licitacoes .auctions-grid');
        
        if (bids.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <h3>Ainda não fez nenhuma licitação</h3>
                    <p>Explore os leilões ativos e faça a sua primeira licitação!</p>
                    <button class="btn-primary" onclick="navigateTo('leiloes')">VER LEILÕES</button>
                </div>
            `;
            return;
        }
        
        // Agrupar por leilão
        const bidsByAuction = {};
        for (const bid of bids) {
            if (!bidsByAuction[bid.auction_id]) {
                bidsByAuction[bid.auction_id] = [];
            }
            bidsByAuction[bid.auction_id].push(bid);
        }
        
        // Criar cards
        let html = '';
        for (const auctionId in bidsByAuction) {
            const auctionBids = bidsByAuction[auctionId];
            const highestBid = auctionBids.reduce((max, bid) => bid.value > max.value ? bid : max);
            
            html += `
                <div class="auction-card">
                    <div class="auction-content">
                        <h3 class="auction-title">Leilão: ${auctionId.substring(0, 8)}...</h3>
                        <div class="auction-info">
                            <div class="info-item">
                                <span class="info-label">Suas licitações:</span>
                                <span class="info-value">${auctionBids.length}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Maior valor:</span>
                                <span class="info-value">€${highestBid.value.toFixed(2)}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Última licitação:</span>
                                <span class="info-value">${new Date(highestBid.timestamp).toLocaleString('pt-PT')}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        grid.innerHTML = html;
        
    } catch (error) {
        console.error('Erro ao carregar licitações:', error);
        showNotification('Erro ao carregar suas licitações!', 'error');
    }
}

// ==================== CRIAR LEILÃO ====================

function setupForms() {
    const formCriarLeilao = document.getElementById('formCriarLeilao');
    if (formCriarLeilao) {
        formCriarLeilao.addEventListener('submit', handleCreateAuction);
    }
    
    // Set minimum date to today
    const dataEncerramento = document.getElementById('dataEncerramento');
    if (dataEncerramento) {
        const today = new Date().toISOString().split('T')[0];
        dataEncerramento.min = today;
    }
    
    // Login/Register buttons
    const btnLogin = document.getElementById('btnLogin');
    const btnRegister = document.getElementById('btnRegister');
    
    if (btnLogin) btnLogin.addEventListener('click', () => navigateTo('login'));
    if (btnRegister) btnRegister.addEventListener('click', () => navigateTo('register'));
}

async function handleCreateAuction(e) {
    e.preventDefault();
    
    const item = document.getElementById('itemDescricao').value;
    const dataEncerramento = document.getElementById('dataEncerramento').value;
    const horaEncerramento = document.getElementById('horaEncerramento').value;
    const minBid = document.getElementById('precoMinimo').value;
    const categoria = document.getElementById('categoria').value;
    
    // Combinar data e hora no formato ISO
    const closingDate = `${dataEncerramento}T${horaEncerramento}:00`;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                item: item,
                closing_date: closingDate,
                min_bid: minBid ? parseFloat(minBid) : null,
                categoria: categoria
            })
        });
        
        if (!response.ok) {
            throw new Error('Erro ao criar leilão');
        }
        
        const auction = await response.json();
        console.log('Leilão criado:', auction);
        
        showNotification('Leilão criado com sucesso e enviado para a rede P2P!', 'success');
        
        // Reset form
        e.target.reset();
        
        // Navigate to my auctions
        navigateTo('meus-leiloes');
        
    } catch (error) {
        console.error('Erro ao criar leilão:', error);
        showNotification('Erro ao criar leilão!', 'error');
    }
}

// ==================== LICITAR ====================

function showBidModal(auctionId, itemName, minBid) {
    const bidValue = prompt(`Fazer licitação em: ${itemName}\n\nPreço mínimo: €${minBid.toFixed(2)}\n\nInsira o valor da sua licitação (€):`);
    
    if (bidValue === null) return; // Cancelado
    
    const value = parseFloat(bidValue);
    
    if (isNaN(value) || value <= 0) {
        alert('Valor inválido!');
        return;
    }
    
    if (minBid && value < minBid) {
        alert(`O valor deve ser pelo menos €${minBid.toFixed(2)}!`);
        return;
    }
    
    placeBid(auctionId, value);
}

async function placeBid(auctionId, value) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/bids`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                auction_id: auctionId,
                value: value
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Erro ao fazer licitação');
        }
        
        const bid = await response.json();
        console.log('Licitação feita:', bid);
        
        showNotification(`Licitação de €${value.toFixed(2)} enviada com sucesso!`, 'success');
        
        // Recarregar leilões
        await loadActiveAuctions();
        
    } catch (error) {
        console.error('Erro ao fazer licitação:', error);
        alert(`Erro: ${error.message}`);
    }
}

// ==================== NOTIFICAÇÕES ====================

function showNotification(message, type = 'info') {
    // Por agora usa alert simples
    // TODO: Implementar sistema de notificações bonito
    alert(message);
}

// ==================== EXPORT ====================

window.navigateTo = navigateTo;
window.showBidModal = showBidModal;
window.viewAuctionBids = viewAuctionBids;
window.viewWinner = viewWinner;

// ==================== FILTROS ====================

let currentFilters = {
    searchTerm: '',
    categoria: '',
    precoMinimo: '',
    estado: '',
    ordenarPor: ''
};

function setupFilters() {
    const btnFilter = document.querySelector('.btn-filter');
    
    if (btnFilter) {
        btnFilter.addEventListener('click', applyFilters);
    }
    
    // Enter para pesquisar
    const searchInput = document.querySelector('.filter-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                applyFilters();
            }
        });
    }
    
    // Limpar filtros ao navegar para leilões
    const navLeiloes = document.querySelector('[data-page="leiloes"]');
    if (navLeiloes) {
        navLeiloes.addEventListener('click', function() {
            setTimeout(resetFilters, 100);
        });
    }
}

function resetFilters() {
    const searchInput = document.querySelector('.filter-input');
    const selects = document.querySelectorAll('.filter-select');
    
    if (searchInput) searchInput.value = '';
    selects.forEach(select => select.selectedIndex = 0);
    
    currentFilters = {
        searchTerm: '',
        categoria: '',
        precoMinimo: '',
        estado: '',
        ordenarPor: ''
    };
    
    loadActiveAuctions();
}

async function applyFilters() {
    // Obter valores dos filtros de forma mais robusta
    const filtersContainer = document.querySelector('.filters-sidebar');
    if (!filtersContainer) return;
    
    const searchInput = filtersContainer.querySelector('.filter-input');
    const selects = filtersContainer.querySelectorAll('.filter-select');
    
    currentFilters.searchTerm = searchInput?.value.trim().toLowerCase() || '';
    currentFilters.categoria = selects[0]?.value || '';
    currentFilters.precoMinimo = selects[1]?.value || '';
    currentFilters.estado = selects[2]?.value || '';
    currentFilters.ordenarPor = selects[3]?.value || '';
    
    console.log('Aplicando filtros:', currentFilters);
    
    try {
        // Mostrar loading
        const grid = document.querySelector('#page-leiloes .auctions-grid');
        grid.innerHTML = '<div style="text-align: center; padding: 40px;">Carregando...</div>';
        
        // Carregar todos os leilões
        const response = await fetch(`${API_BASE_URL}/api/auctions/active`);
        
        if (!response.ok) {
            throw new Error('Erro ao carregar leilões');
        }
        
        let auctions = await response.json();
        console.log(`Total de leilões: ${auctions.length}`);
        
        // APLICAR FILTROS
        auctions = filterAuctions(auctions);
        
        console.log(`Após filtros: ${auctions.length} leilões`);
        
        // Renderizar resultados
        renderFilteredAuctions(auctions);
        
    } catch (error) {
        console.error('Erro ao aplicar filtros:', error);
        showNotification('Erro ao aplicar filtros!', 'error');
        
        // Mostrar erro na UI
        const grid = document.querySelector('#page-leiloes .auctions-grid');
        grid.innerHTML = `
            <div class="empty-state">
                <h3>Erro ao carregar leilões</h3>
                <p>${error.message}</p>
                <button class="btn-primary" onclick="loadActiveAuctions()">TENTAR NOVAMENTE</button>
            </div>
        `;
    }
}

function filterAuctions(auctions) {
    let filtered = [...auctions];
    
    // FILTRO 1: Pesquisa por texto
    if (currentFilters.searchTerm) {
        filtered = filtered.filter(auction => 
            auction.item.toLowerCase().includes(currentFilters.searchTerm)
        );
        console.log(`  └─ Após pesquisa "${currentFilters.searchTerm}": ${filtered.length}`);
    }
    
    // FILTRO 2: Categoria
    if (currentFilters.categoria) {
        filtered = filtered.filter(auction => {
            if (!auction.categoria) return false;
            
            // Normaliza AMBOS para comparar (lowercase, sem acentos)
            const filterCat = currentFilters.categoria.toLowerCase()
                .normalize("NFD").replace(/[\u0300-\u036f]/g, "");
            const auctionCat = auction.categoria.toLowerCase()
                .normalize("NFD").replace(/[\u0300-\u036f]/g, "");
            
            return auctionCat === filterCat;
        });
        console.log(`  └─ Após filtro categoria "${currentFilters.categoria}": ${filtered.length}`);
    }
    
    // FILTRO 3: Preço mínimo
    if (currentFilters.precoMinimo) {
        const [min, max] = parsePrecoRange(currentFilters.precoMinimo);
        
        filtered = filtered.filter(auction => {
            const price = auction.min_bid || 0;
            
            if (max === null) {
                return price >= min; // Ex: 1000+
            }
            
            return price >= min && price <= max;
        });
        
        console.log(`  └─ Após filtro preço (${min}-${max || '∞'}): ${filtered.length}`);
    }
    
    // FILTRO 4: Estado (aberto/encerrado)
    if (currentFilters.estado) {
        const now = new Date();
        
        if (currentFilters.estado === 'aberto') {
            filtered = filtered.filter(auction => {
                const closingDate = new Date(auction.closing_date);
                return closingDate > now;
            });
        } else if (currentFilters.estado === 'encerrado') {
            filtered = filtered.filter(auction => {
                const closingDate = new Date(auction.closing_date);
                return closingDate <= now;
            });
        }
        
        console.log(`  └─ Após filtro estado "${currentFilters.estado}": ${filtered.length}`);
    }
    
    // ORDENAÇÃO
    if (currentFilters.ordenarPor) {
        switch (currentFilters.ordenarPor) {
            case 'recentes':
                // Mais recentes primeiro (assumindo que created_at existe ou usando auction_id)
                filtered.sort((a, b) => b.auction_id.localeCompare(a.auction_id));
                console.log('  └─ Ordenado por: Mais Recentes');
                break;
                
            case 'termina-breve':
                // Fecha mais cedo primeiro
                filtered.sort((a, b) => {
                    const dateA = new Date(a.closing_date);
                    const dateB = new Date(b.closing_date);
                    return dateA - dateB;
                });
                console.log('  └─ Ordenado por: Termina Breve');
                break;
                
            case 'preco-baixo':
                // Preço mais baixo primeiro
                filtered.sort((a, b) => (a.min_bid || 0) - (b.min_bid || 0));
                console.log('  └─ Ordenado por: Preço Baixo → Alto');
                break;
                
            case 'preco-alto':
                // Preço mais alto primeiro
                filtered.sort((a, b) => (b.min_bid || 0) - (a.min_bid || 0));
                console.log('  └─ Ordenado por: Preço Alto → Baixo');
                break;
        }
    }
    
    return filtered;
}

function parsePrecoRange(value) {
    if (!value || value === '') return [0, null];
    
    // "0-100" -> [0, 100]
    if (value.includes('-')) {
        const parts = value.split('-');
        const min = parseInt(parts[0]) || 0;
        const max = parseInt(parts[1]) || 0;
        return [min, max];
    }
    
    // "1000+" -> [1000, null]
    if (value.includes('+')) {
        const min = parseInt(value.replace('+', '')) || 0;
        return [min, null];
    }
    
    return [0, null];
}

function renderFilteredAuctions(auctions) {
    const grid = document.querySelector('#page-leiloes .auctions-grid');
    
    if (!grid) {
        console.error('Grid não encontrado!');
        return;
    }
    
    if (auctions.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <h3>Nenhum leilão encontrado</h3>
                <p>Tente ajustar os filtros ou criar um novo leilão!</p>
                <div style="display: flex; gap: 10px; justify-content: center; margin-top: 20px;">
                    <button class="btn-secondary" onclick="resetFilters()">LIMPAR FILTROS</button>
                    <button class="btn-primary" onclick="navigateTo('criar')">CRIAR LEILÃO</button>
                </div>
            </div>
        `;
        return;
    }
    
    // Renderizar cards
    grid.innerHTML = auctions.map(auction => createAuctionCard(auction)).join('');
    
    // Mostrar contador de resultados
    console.log(`Mostrar ${auctions.length} leilão(ões)`);
}