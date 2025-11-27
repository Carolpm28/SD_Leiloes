// ==================== CONFIGURAÇÃO ====================

// URL base da API - mudar isto dependendo do cliente
const API_BASE_URL = `http://${window.location.hostname}:5001`;

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

async function initializeApp() {
    console.log('Inicializando aplicação...');
    
    // Verificar conexão com API
    checkAPIConnection();
    setupFilters();
    
    // Verificar se esta autenticado
    await checkAuthStatus();
    
    // Configurar auto-refresh
    setInterval(refreshAuctions, 30000);
}

async function checkAuthStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/status?discover=true`);
        const data = await response.json();
        
        if (data.authenticated) {
            // Utilizador está autenticado
            console.log(`Authenticated as ${data.username}`);
            console.log('Peers re-discovered automatically');  
            updateUIForAuthenticatedUser(data.username);
        } else {
            // Não autenticado - mostrar botões de login/registo
            console.log('Not authenticated');
            updateUIForGuestUser();
        }
    } catch (error) {
        console.error('Erro ao verificar autenticação:', error);
        updateUIForGuestUser();
    }
}

function updateUIForAuthenticatedUser(username) {
    // Esconder botões de login/registo
    document.getElementById('btnLogin').style.display = 'none';
    document.getElementById('btnRegister').style.display = 'none';
    
    // Mostrar username e botão de logout
    const userActions = document.querySelector('.user-actions');
    userActions.innerHTML = `
        <span style="color: #6c757d; margin-right: 15px;">👤 ${username}</span>
        <button class="btn-secondary" onclick="logout()">Sair</button>
    `;
}

function updateUIForGuestUser() {
    // Mostrar botões de login/registo normais
    document.getElementById('btnLogin').style.display = 'inline-block';
    document.getElementById('btnRegister').style.display = 'inline-block';
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
            await loadAuctions();
            break;
        case 'meus-leiloes':
            await loadMyAuctions();
            break;
        case 'minhas-licitacoes':
            await loadMyBids();
            break;
    }
}

async function updateNetworkStatus() {
    try {
        const info = await fetch(`${API_BASE_URL}/api/info`).then(r => r.json());
        const count = info.peers_count;
        const status = document.getElementById('peer-count');
        status.textContent = count > 0 ? `${count} peer(s)` : '0 peers';
        status.style.color = count > 0 ? '#28a745' : '#dc3545';
    } catch (error) {
        console.error('Erro ao atualizar status:', error);
    }
}

setInterval(updateNetworkStatus, 5000);

// ==================== CARREGAR DADOS INICIAIS ====================

async function loadInitialData() {
    await loadAuctions();
}

async function refreshAuctions() {
    const currentPage = document.querySelector('.page-section.active');
    if (currentPage && currentPage.id === 'page-leiloes') {
        await loadAuctions();
    }
}

// ==================== FUNÇÕES AUXILIARES ====================

function calculateTimeLeft(closingDate) {
    const now = new Date();
    const closing = new Date(closingDate);
    const diff = closing - now;
    
    if (diff <= 0) {
        return 'Encerrado';
    }
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (days > 0) {
        return `${days}d ${hours}h`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('pt-PT', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// ==================== LEILÕES  ====================

async function loadAuctions() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions`); 
        const auctions = await response.json();
        
        const grid = document.querySelector('#page-leiloes .auctions-grid');
        
        if (auctions.length === 0) {
            grid.innerHTML = `
                <div class="empty-state">
                    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <h3>Nenhum leilão no momento</h3>
                    <p>Seja o primeiro a criar um leilão!</p>
                    <button class="btn-primary" onclick="navigateTo('criar')">CRIAR LEILÃO</button>
                </div>
            `;
            return;
        }
        
        grid.innerHTML = auctions.map(auction => {
            // Calcula estado do leilão
            const closingDate = new Date(auction.closing_date);
            const now = new Date();
            const isActive = closingDate > now;
            const status = isActive ? 'Ativo' : 'Encerrado';
            const badgeClass = isActive ? 'badge-active' : 'badge-closed';
            
            // Calcula tempo restante
            const timeLeft = calculateTimeLeft(auction.closing_date);
            
            return `
                <div class="auction-card ${isActive ? '' : 'auction-closed'}" data-id="${auction.auction_id}" data-status="${isActive ? 'active' : 'closed'}">
                    <div class="auction-image">
                        <img src="https://via.placeholder.com/300x200?text=${encodeURIComponent(auction.item)}" alt="${auction.item}">
                        <span class="auction-badge ${badgeClass}">${status}</span>
                    </div>
                    <div class="auction-content">
                        <h3 class="auction-title">${auction.item}</h3>
                        <div class="auction-details">
                            <div class="auction-detail-item">
                                <span class="detail-label">Preço Mínimo:</span>
                                <span class="detail-value">€${auction.min_bid ? auction.min_bid.toFixed(2) : '0.00'}</span>
                            </div>
                            <div class="auction-detail-item">
                                <span class="detail-label">${isActive ? 'Termina em:' : 'Encerrado há:'}</span>
                                <span class="detail-value">${timeLeft}</span>
                            </div>
                            <div class="auction-detail-item">
                                <span class="detail-label">Data de Encerramento:</span>
                                <span class="detail-value">${formatDateTime(auction.closing_date)}</span>
                            </div>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn-primary btn-full" onclick="viewAuctionDetails('${auction.auction_id}')">
                                    VER DETALHES E LICITAR
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Erro ao carregar leilões:', error);
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
            <div style="display: flex; gap: 10px;">
                <button class="btn-primary btn-full" onclick="viewAuctionDetails('${auction.auction_id}')">
                         VER DETALHES E LICITAR
                </button>
            </div>
        </div>
    </div>
`;
}

// ==================== MEUS LEILÕES ====================

async function loadMyAuctions() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/mine`);
        const auctions = await response.json();
        
        console.log('OsMeus leilões carregados:', auctions.length);
        
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
        console.error('Erro ao carregar os meus leilões:', error);
        showNotification('Erro ao carregar os seus leilões!', 'error');
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
                    <button class="btn-primary btn-full" onclick="viewAuctionDetails('${auction.auction_id}')">
                            VER DETALHES E LICITAR
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
        alert(`Vencedor Atual:\n\nValor: €${winner.value.toFixed(2)}\nData: ${new Date(winner.timestamp).toLocaleString('pt-PT')}`);
        
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

async function handleCreateAuction(e) {
    e.preventDefault();
    
    // VERIFICAR AUTENTICAÇÃO
    const authCheck = await fetch(`${API_BASE_URL}/api/auth/status`);
    const authData = await authCheck.json();
    
    if (!authData.authenticated) {
        alert('Precisa fazer login primeiro!');
        navigateTo('login');
        return;
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

    // REGISTO
    const formRegister = document.getElementById('formRegister');
    if (formRegister) {
        formRegister.addEventListener('submit', handleRegister);
    }
    
    // LOGIN
    const formLogin = document.getElementById('formLogin');
    if (formLogin) {
        formLogin.addEventListener('submit', handleLogin);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    const passwordConfirm = document.getElementById('registerPasswordConfirm').value;
    
    // Validações
    if (!username || !password) {
        alert('Preencha todos os campos obrigatórios!');
        return;
    }
    
    if (password !== passwordConfirm) {
        alert('As passwords não coincidem!');
        return;
    }
    
    if (password.length < 8) {
        alert('Password deve ter pelo menos 8 caracteres!');
        return;
    }
    
    try {
        // Mostrar loading
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'A registar...';
        submitBtn.disabled = true;
        
        // Chamar API
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Sucesso!
            alert(`✓ Registo bem-sucedido!\nBem-vindo, ${data.username}!`);
            
            // Reset form
            e.target.reset();
            
            // Atualizar UI
            updateUIForAuthenticatedUser(data.username);
            
            // Navegar para página inicial
            navigateTo('leiloes');
            
        } else {
            // Erro
            alert(`Erro: ${data.error || 'Registo falhou'}`);
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
        }
        
    } catch (error) {
        console.error('Erro ao registar:', error);
        alert('Erro ao conectar ao servidor!');
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginEmail').value; // Usa o mesmo campo
    const password = document.getElementById('loginPassword').value;
    
    // Validações
    if (!username || !password) {
        alert('Preencha todos os campos!');
        return;
    }
    
    try {
        // Mostrar loading
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'A entrar...';
        submitBtn.disabled = true;
        
        // Chamar API
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Sucesso!
            console.log('Login successful');
            console.log('Peers discovered automatically on server');
            alert(`Login bem-sucedido!\nBem-vindo de volta, ${data.username}!`);
            
            // Reset form
            e.target.reset();
            
            // Atualizar UI
            updateUIForAuthenticatedUser(data.username);
            
            // Navegar para página inicial
            navigateTo('leiloes');
            
        } else {
            // Erro
            alert(`Erro: ${data.error || 'Login falhou'}`);
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
        }
        
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        alert('Erro ao conectar ao servidor!');
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

function logout() {
    if (confirm('Tem a certeza que deseja sair?')) {
        // Não há endpoint de logout no servidor
        // Apenas atualiza UI
        alert('✓ Sessão terminada!');
        updateUIForGuestUser();
        navigateTo('login');
    }
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
    const authCheck = await fetch(`${API_BASE_URL}/api/auth/status`);
    const authData = await authCheck.json();
    
    if (!authData.authenticated) {
        alert('Precisa fazer login primeiro!');
        navigateTo('login');
        return;
    }
    
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
        await loadAuctions();
        
    } catch (error) {
        console.error('Erro ao fazer licitação:', error);
        alert(`Erro: ${error.message}`);
    }
}

// ==================== NOTIFICAÇÕES ====================

function showNotification(message, type = 'info') {
    // Por agora usa alert simples
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
    
    loadAuctions();
}

async function applyFilters() {
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
        const grid = document.querySelector('#page-leiloes .auctions-grid');
        grid.innerHTML = '<div style="text-align: center; padding: 40px;">Carregando...</div>';
        
        const response = await fetch(`${API_BASE_URL}/api/auctions`); 
        
        if (!response.ok) {
            throw new Error('Erro ao carregar leilões');
        }
        
        let auctions = await response.json();
        console.log(`Total de leilões: ${auctions.length}`);
        
        //Marcar cada leilão como ativo ou encerrado
        auctions = auctions.map(auction => {
            const closingDate = new Date(auction.closing_date);
            const now = new Date();
            auction.isActive = closingDate > now;
            auction.status = auction.isActive ? 'active' : 'closed';
            return auction;
        });
        
        // Aplicar filtros
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
                <button class="btn-primary" onclick="loadAuctions()">TENTAR NOVAMENTE</button>
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
    grid.innerHTML = auctions.map(auction => {
        // Calcula estado do leilão novamente
        const closingDate = new Date(auction.closing_date);
        const now = new Date();
        const isActive = closingDate > now;
        const status = isActive ? 'Ativo' : 'Encerrado';
        const badgeClass = isActive ? 'badge-active' : 'badge-closed';
        const timeLeft = calculateTimeLeft(auction.closing_date);
        
        return `
            <div class="auction-card ${isActive ? '' : 'auction-closed'}" data-id="${auction.auction_id}">
                <div class="auction-image">
                    <img src="https://via.placeholder.com/300x200?text=${encodeURIComponent(auction.item)}" alt="${auction.item}">
                    <span class="auction-badge ${badgeClass}">${status}</span>
                </div>
                <div class="auction-content">
                    <h3 class="auction-title">${auction.item}</h3>
                    <div class="auction-details">
                        <div class="auction-detail-item">
                            <span class="detail-label">Preço Mínimo:</span>
                            <span class="detail-value">€${auction.min_bid ? auction.min_bid.toFixed(2) : '0.00'}</span>
                        </div>
                        <div class="auction-detail-item">
                            <span class="detail-label">${isActive ? 'Termina em:' : 'Encerrado há:'}</span>
                            <span class="detail-value">${timeLeft}</span>
                        </div>
                        <div class="auction-detail-item">
                            <span class="detail-label">Data de Encerramento:</span>
                            <span class="detail-value">${formatDateTime(auction.closing_date)}</span>
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                    <button class="btn-primary btn-full" onclick="viewAuctionDetails('${auction.auction_id}')">
                            VER DETALHES E LICITAR
                    </button>
                </div>
                </div>
            </div>
        `;
    }).join('');
    
    console.log(`Renderizados ${auctions.length} leilão(ões)`);
}

// ==================== PÁGINA DE DETALHES DO LEILÃO ====================

let currentAuctionId = null;
let detalhesInterval = null;

async function viewAuctionDetails(auctionId) {
    currentAuctionId = auctionId;
    navigateTo('detalhes');
    
    await loadAuctionDetails(auctionId);
    await loadAuctionBids(auctionId);
    
    // Atualizar timer e bids a cada 1 segundo
    if (detalhesInterval) clearInterval(detalhesInterval);
    detalhesInterval = setInterval(() => {
        updateCountdownTimer();
        loadAuctionBids(auctionId); // Atualiza bids em tempo real
    }, 1000);
}

async function loadAuctionDetails(auctionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/${auctionId}`);
        const auction = await response.json();
        
        // Título
        document.getElementById('detalhes-titulo').textContent = auction.item;
        
        // Detalhes
        document.getElementById('detalhes-preco-minimo').textContent = 
            auction.min_bid ? `€${auction.min_bid.toFixed(2)}` : 'Sem mínimo';
        
        document.getElementById('detalhes-categoria').textContent = 
            getCategoriaLabel(auction.categoria);
        
        const closingDate = new Date(auction.closing_date);
        document.getElementById('detalhes-data').textContent = 
            closingDate.toLocaleString('pt-PT');
        
        // Estado
        const now = new Date();
        const estado = document.getElementById('detalhes-estado');
        if (closingDate > now) {
            estado.textContent = 'Ativo';
            estado.className = 'detalhes-badge';
        } else {
            estado.textContent = 'Encerrado';
            estado.className = 'detalhes-badge encerrado';
            document.getElementById('detalhes-form-container').style.display = 'none';
        }
        
        // Guardar para countdown
        window.currentAuction = auction;
        updateCountdownTimer();
        
        // Hint do formulário
        const hint = document.getElementById('bid-min-hint');
        hint.textContent = auction.min_bid 
            ? `Valor mínimo: €${auction.min_bid.toFixed(2)}`
            : 'Digite o valor da sua proposta';
        
    } catch (error) {
        console.error('Erro ao carregar detalhes:', error);
        showNotification('Erro ao carregar leilão', 'error');
    }
}

async function loadAuctionBids(auctionId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auctions/${auctionId}/bids`);
        const bids = await response.json();
        
        const timeline = document.getElementById('bids-timeline');
        
        if (bids.length === 0) {
            timeline.innerHTML = `
                <div class="bids-empty">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <p>Nenhuma licitação ainda</p>
                    <small>Seja o primeiro a fazer uma proposta!</small>
                </div>
            `;
            
            // Esconder bid atual
            document.getElementById('detalhes-bid-container').style.display = 'none';
            return;
        }
        
        // Ordenar do mais recente para o mais antigo
        bids.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        // Mostrar bid mais alto
        const highestBid = bids[0];
        document.getElementById('detalhes-bid-container').style.display = 'block';
        document.getElementById('detalhes-bid-valor').textContent = `€${highestBid.value.toFixed(2)}`;
        document.getElementById('detalhes-bid-info').textContent = 
            `${bids.length} licitação(ões) • Última há ${getTimeAgo(highestBid.timestamp)}`;
        
        // Renderizar timeline
        timeline.innerHTML = bids.map((bid, index) => {
            const isWinning = index === 0;
            const isMine = bid.is_mine === 1;
            
            let classes = 'bid-item';
            if (isMine) classes += ' my-bid';
            if (isWinning) classes += ' winning';
            
            let badges = '';
            if (isMine) badges += '<span class="bid-badge meu">MEU BID</span>';
            if (isWinning) badges += '<span class="bid-badge vencedor"> A Ganhar</span>';
            
            return `
                <div class="${classes}">
                    <div class="bid-icon">${isWinning ? '' : ''}</div>
                    <div class="bid-content">
                        <div class="bid-value">€${bid.value.toFixed(2)}</div>
                        <div class="bid-info">
                            <span>${getTimeAgo(bid.timestamp)}</span>
                            ${badges}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Erro ao carregar bids:', error);
    }
}

function updateCountdownTimer() {
    if (!window.currentAuction) return;
    
    const closingDate = new Date(window.currentAuction.closing_date);
    const now = new Date();
    const diff = closingDate - now;
    
    const timerElement = document.getElementById('detalhes-timer');
    const countdownElement = document.querySelector('.detalhes-countdown');
    
    if (diff <= 0) {
        timerElement.textContent = 'Leilão Encerrado';
        countdownElement.className = 'detalhes-countdown encerrado';
        if (detalhesInterval) {
            clearInterval(detalhesInterval);
        }
        return;
    }
    
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    let timeString = '';
    if (days > 0) timeString += `${days}d `;
    if (hours > 0 || days > 0) timeString += `${hours}h `;
    timeString += `${minutes}m ${seconds}s`;
    
    timerElement.textContent = `Termina em: ${timeString}`;
    
    // Marcar como urgente se falta menos de 1 hora
    if (diff < 3600000) {
        countdownElement.className = 'detalhes-countdown urgente';
    } else {
        countdownElement.className = 'detalhes-countdown';
    }
}

function getTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diff = now - past;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `há ${days} dia${days > 1 ? 's' : ''}`;
    if (hours > 0) return `há ${hours} hora${hours > 1 ? 's' : ''}`;
    if (minutes > 0) return `há ${minutes} minuto${minutes > 1 ? 's' : ''}`;
    return `há ${seconds} segundo${seconds !== 1 ? 's' : ''}`;
}

function getCategoriaLabel(categoria) {
    const labels = {
        'eletronicos': 'Eletrónicos',
        'imoveis': 'Imóveis',
        'veiculos': 'Veículos',
        'arte': 'Arte e Colecionáveis',
        'outros': 'Outros'
    };
    return labels[categoria] || categoria || 'Sem categoria';
}

// Handler do formulário de bid
document.getElementById('formFazerBid')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const value = parseFloat(document.getElementById('bidValue').value);
    
    if (!currentAuctionId) {
        showNotification('Erro: Leilão não identificado', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/bids`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                auction_id: currentAuctionId,
                value: value
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Erro ao criar bid');
        }
        
        showNotification('Licitação enviada com sucesso!', 'success');
        document.getElementById('bidValue').value = '';
        
        // Recarregar bids
        await loadAuctionBids(currentAuctionId);
        
    } catch (error) {
        console.error('Erro ao fazer bid:', error);
        showNotification(error.message, 'error');
    }
});

// Limpar interval quando sair da página
const originalNavigateTo = navigateTo;
navigateTo = function(page) {
    if (detalhesInterval && page !== 'detalhes') {
        clearInterval(detalhesInterval);
        detalhesInterval = null;
    }
    originalNavigateTo(page);
};

