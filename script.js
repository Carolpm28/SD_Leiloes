// Navigation System
document.addEventListener('DOMContentLoaded', function() {
    // Get all navigation links
    const navLinks = document.querySelectorAll('.nav-link');
    
    // Add click event to each navigation link
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the page to show
            const pageToShow = this.getAttribute('data-page');
            
            // Navigate to the page
            navigateTo(pageToShow);
        });
    });

    // Handle form submission
    const formCriarLeilao = document.getElementById('formCriarLeilao');
    if (formCriarLeilao) {
        formCriarLeilao.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const formData = {
                descricao: document.getElementById('itemDescricao').value,
                detalhes: document.getElementById('itemDetalhes').value,
                categoria: document.getElementById('categoria').value,
                precoMinimo: document.getElementById('precoMinimo').value,
                dataEncerramento: document.getElementById('dataEncerramento').value,
                horaEncerramento: document.getElementById('horaEncerramento').value,
                imagem: document.getElementById('imagemItem').files[0]
            };
            
            console.log('Criar leilão:', formData);
            
            // Show success message (temporary)
            alert('Leilão criado com sucesso!\n\nEsta é uma versão de demonstração. Em produção, os dados seriam enviados para o sistema P2P.');
            
            // Reset form
            this.reset();
            
            // Navigate to "Meus Leilões"
            navigateTo('meus-leiloes');
        });
    }

    // Set minimum date to today for auction end date
    const dataEncerramento = document.getElementById('dataEncerramento');
    if (dataEncerramento) {
        const today = new Date().toISOString().split('T')[0];
        dataEncerramento.min = today;
    }
});

/**
 * Navigate to a specific page
 * @param {string} pageName - The name of the page to navigate to
 */
function navigateTo(pageName) {
    // Hide all page sections
    const allPages = document.querySelectorAll('.page-section');
    allPages.forEach(page => {
        page.classList.remove('active');
    });
    
    // Show the selected page
    const selectedPage = document.getElementById(`page-${pageName}`);
    if (selectedPage) {
        selectedPage.classList.add('active');
    }
    
    // Update active nav link
    const allNavLinks = document.querySelectorAll('.nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === pageName) {
            link.classList.add('active');
        }
    });
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Filter functionality
document.addEventListener('DOMContentLoaded', function() {
    const btnFilter = document.querySelector('.btn-filter');
    
    if (btnFilter) {
        btnFilter.addEventListener('click', function() {
            // Get filter values
            const searchTerm = document.querySelector('.filter-input').value;
            const categoria = document.querySelector('.filter-select').value;
            
            console.log('Aplicar filtros:', {
                searchTerm,
                categoria
            });
            
            // In production, this would filter the auction cards
            alert('Filtros aplicados!\n\nEsta é uma versão de demonstração. Em produção, os leilões seriam filtrados.');
        });
    }
});

// Auction card buttons
document.addEventListener('DOMContentLoaded', function() {
    // Add event listeners to all auction buttons
    document.addEventListener('click', function(e) {
        // Handle "VER DETALHES E LICITAR" button
        if (e.target.classList.contains('btn-auction')) {
            const card = e.target.closest('.auction-card');
            const title = card.querySelector('.auction-title').textContent;
            
            console.log('Ver detalhes do leilão:', title);
            alert(`Ver detalhes e licitar: ${title}\n\nEsta funcionalidade será implementada na próxima fase.`);
        }
        
        // Handle "CANCELAR LEILÃO" button
        if (e.target.classList.contains('btn-danger')) {
            const card = e.target.closest('.auction-card');
            const title = card.querySelector('.auction-title').textContent;
            
            if (confirm(`Tem certeza que deseja cancelar o leilão "${title}"?`)) {
                console.log('Cancelar leilão:', title);
                alert('Leilão cancelado com sucesso!');
                // In production, remove the card or update its status
            }
        }
    });
});

// Login and Register buttons
document.addEventListener('DOMContentLoaded', function() {
    const btnLogin = document.getElementById('btnLogin');
    const btnRegister = document.getElementById('btnRegister');
    
    if (btnLogin) {
        btnLogin.addEventListener('click', function() {
            navigateTo('login');
        });
    }
    
    if (btnRegister) {
        btnRegister.addEventListener('click', function() {
            navigateTo('register');
        });
    }

    // Handle login form submission
    const formLogin = document.getElementById('formLogin');
    if (formLogin) {
        formLogin.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            const rememberMe = document.getElementById('rememberMe').checked;
            
            console.log('Login attempt:', { email, rememberMe });
            
            // Simulate login process
            alert('Login bem-sucedido!\n\nEsta é uma versão de demonstração.\n\nEm produção:\n✓ Autenticação segura\n✓ Validação de credenciais\n✓ Carregamento de chaves criptográficas');
            
            // Navigate to main page
            navigateTo('leiloes');
            
            // Update UI to show logged in state (future implementation)
            updateLoginState(email);
        });
    }

    // Handle register form submission
    const formRegister = document.getElementById('formRegister');
    if (formRegister) {
        formRegister.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('registerName').value;
            const email = document.getElementById('registerEmail').value;
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;
            const passwordConfirm = document.getElementById('registerPasswordConfirm').value;
            const acceptTerms = document.getElementById('acceptTerms').checked;
            
            // Validate passwords match
            if (password !== passwordConfirm) {
                alert('As palavras-passe não coincidem!');
                return;
            }
            
            // Validate password strength
            if (password.length < 8) {
                alert('A palavra-passe deve ter pelo menos 8 caracteres!');
                return;
            }
            
            if (!acceptTerms) {
                alert('Deve aceitar os termos e condições!');
                return;
            }
            
            console.log('Register attempt:', { name, email, username });
            
            // Simulate registration process
            alert('Registo bem-sucedido!\n\n✓ Conta criada\n✓ Par de chaves criptográficas gerado\n✓ Registo no servidor de descoberta\n\nVerifique o seu email para ativar a conta.');
            
            // Navigate to login page
            navigateTo('login');
            
            // Pre-fill email in login form
            setTimeout(() => {
                const loginEmail = document.getElementById('loginEmail');
                if (loginEmail) {
                    loginEmail.value = email;
                }
            }, 100);
        });
    }
});

// Update login state (placeholder for future implementation)
function updateLoginState(email) {
    console.log('User logged in:', email);
    // Future: Update header buttons to show user profile
    // Future: Enable auction creation and bidding
}

// Update auction countdown (example for future implementation)
function updateCountdowns() {
    // This would update countdown timers on auction cards
    // To be implemented in production
}

// Auto-update every minute
setInterval(updateCountdowns, 60000);

// Form validation helpers
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;
    
    // Check if form is valid
    if (!form.checkValidity()) {
        form.reportValidity();
        return false;
    }
    
    return true;
}

// Export navigation function for inline onclick handlers
window.navigateTo = navigateTo;