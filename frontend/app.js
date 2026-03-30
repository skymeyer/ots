document.addEventListener('DOMContentLoaded', init);

const views = {
    loading: document.getElementById('loading-view'),
    auth: document.getElementById('auth-view'),
    dashboard: document.getElementById('dashboard-view'),
    reveal: document.getElementById('reveal-view')
};

// State
let currentPath = window.location.pathname;
let secretId = null;
let appConfig = { contact_email: "", max_secret_length: 1024 };

function showView(viewId) {
    Object.values(views).forEach(el => el.classList.remove('active'));
    views[viewId].classList.add('active');
}

async function init() {
    try {
        const res = await fetch('/api/config');
        if (res.ok) {
            Object.assign(appConfig, await res.json());
        }
    } catch(err) {
        console.warn("Failed fetching config", err);
    }
    
    if (appConfig.hide_footer) {
        const footer = document.getElementById('site-footer');
        if (footer) footer.style.display = 'none';
    }

    initCookieConsent();

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('error') === 'unauthorized') {
        history.replaceState(null, '', window.location.pathname);
        showUnauthorizedModal();
    }

    // Determine if we're on the landing page or a reveal page
    if (currentPath.startsWith('/s/')) {
        secretId = currentPath.split('/s/')[1];
        if (secretId) {
            await handleRevealFlow();
            return;
        }
    }

    // Default flow: check auth and show dashboard
    checkAuth();
}

async function checkAuth() {
    try {
        const response = await fetch('/api/auth/me');
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                document.getElementById('user-email').textContent = data.email;
                if (data.picture) {
                    const picEl = document.getElementById('user-picture');
                    if (picEl) {
                        picEl.src = data.picture;
                        picEl.style.display = 'block';
                    }
                }
                showView('dashboard');
                setupDashboard();
                return;
            }
        }
        setupAuthFallback();
        showView('auth');
    } catch (e) {
        console.error("Auth check failed", e);
        setupAuthFallback();
        showView('auth');
    }
}

// Just in case Google Auth is not configured on the backend
async function setupAuthFallback() {
    const devFallback = document.getElementById('dev-login-fallback');
    // We could ping a metadata endpoint to check if google client ID is configured 
    // but for simplicity we just render a dev login link if URL has ?dev=1
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('dev')) {
        devFallback.innerHTML = `
            <hr style="margin: 20px 0; border-color: var(--border-color);">
            <form action="/api/auth/devlogin" method="POST">
                <input type="email" name="email" value="admin@example.com" style="width:100%; padding:0.5rem; margin-bottom:10px; border-radius:4px;" />
                <button type="submit" class="btn secondary-btn" style="width:100%">Dev Login</button>
            </form>
        `;
    }
}

function setupDashboard() {
    const form = document.getElementById('create-secret-form');
    const input = document.getElementById('secret-input');
    const charCount = document.getElementById('char-count');
    const maxLength = appConfig.max_secret_length || 1024;
    
    input.maxLength = maxLength;
    charCount.textContent = `0 / ${maxLength}`;

    input.addEventListener('input', () => {
        const len = input.value.length;
        charCount.textContent = `${len} / ${maxLength}`;
        if (len > maxLength) {
            charCount.style.color = 'var(--danger)';
        } else {
            charCount.style.color = 'var(--text-secondary)';
        }
    });

    const ttlSelect = document.getElementById('ttl-input');
    const ttlCustom = document.getElementById('ttl-custom');
    
    // Enforce limits from config
    const maxTtl = appConfig.max_ttl_hours || 168;
    ttlCustom.max = maxTtl;
    ttlCustom.placeholder = `Max ${maxTtl}h`;
    ttlCustom.disabled = true;

    ttlSelect.addEventListener('change', () => {
        if (ttlSelect.value === 'custom') {
            ttlCustom.classList.remove('hidden');
            ttlCustom.disabled = false;
            ttlCustom.focus();
        } else {
            ttlCustom.classList.add('hidden');
            ttlCustom.disabled = true;
        }
    });

    document.getElementById('create-another-btn').addEventListener('click', () => {
        document.getElementById('result-box').classList.add('hidden');
        document.getElementById('create-secret-container').classList.remove('hidden');
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const secret = input.value;
        if (!secret) return;

        let ttlHours = parseInt(ttlSelect.value, 10);
        if (ttlSelect.value === 'custom') {
            ttlHours = parseInt(ttlCustom.value, 10);
            if (isNaN(ttlHours) || ttlHours < 1) {
                alert("Please enter a valid number of hours.");
                return;
            }
            if (ttlHours > maxTtl) {
                alert(`Maximum allowed time is ${maxTtl} hours.`);
                return;
            }
        }

        try {
            const btn = form.querySelector('button');
            btn.disabled = true;
            btn.textContent = 'Creating...';

            const response = await fetch('/api/secrets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    secret,
                    ttl_hours: ttlHours
                })
            });

            if (!response.ok) {
                const msg = await response.text();
                throw new Error(msg || 'Failed to create secret');
            }

            const data = await response.json();
            
            // Show result / hide form
            document.getElementById('create-secret-container').classList.add('hidden');
            document.getElementById('result-box').classList.remove('hidden');
            const urlInput = document.getElementById('result-url');
            urlInput.value = data.url;
            
            // Setup Copy
            setupCopy('copy-url-btn', urlInput, 'copy-feedback-url');

            // Reset Form Values
            input.value = '';
            charCount.textContent = `0 / ${appConfig.max_secret_length || 1024}`;
            
        } catch (err) {
            alert(err.message);
        } finally {
            const btn = form.querySelector('button');
            btn.disabled = false;
            btn.textContent = 'Create Secret';
        }
    });
}

async function handleRevealFlow() {
    showView('loading');
    
    try {
        // Step 1: Check Metadata without burning
        const metaRes = await fetch(`/api/secrets/${secretId}/metadata`);
        if (!metaRes.ok) {
            showRevealError();
            return;
        }

        // Show Reveal View with warning
        showView('reveal');
        
        const revealBtn = document.getElementById('reveal-btn');
        revealBtn.addEventListener('click', async () => {
            revealBtn.disabled = true;
            revealBtn.textContent = 'Revealing...';
            
            try {
                // Step 2: Actually burn it and reveal
                const revRes = await fetch(`/api/secrets/${secretId}/reveal`, { method: 'POST' });
                if (!revRes.ok) {
                    showRevealError();
                    return;
                }
                
                const data = await revRes.json();
                
                document.getElementById('reveal-pending').classList.add('hidden');
                document.getElementById('reveal-success').classList.remove('hidden');
                
                const secretArea = document.getElementById('revealed-secret');
                secretArea.value = data.value;
                
                setupCopy('copy-secret-btn', secretArea, 'copy-feedback-secret');

            } catch (err) {
                showRevealError();
            }
        });

    } catch (err) {
        showRevealError();
    }
}

function showRevealError() {
    showView('reveal');
    document.getElementById('reveal-pending').classList.add('hidden');
    document.getElementById('reveal-success').classList.add('hidden');
    document.getElementById('reveal-error').classList.remove('hidden');
}

function setupCopy(btnId, inputEl, feedbackId) {
    const btn = document.getElementById(btnId);
    const feedback = document.getElementById(feedbackId);
    
    // Clear old listeners if doing multiple creations without refresh
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);

    newBtn.addEventListener('click', () => {
        inputEl.select();
        inputEl.setSelectionRange(0, 99999); /* For mobile devices */
        navigator.clipboard.writeText(inputEl.value).then(() => {
            feedback.classList.add('show');
            setTimeout(() => {
                feedback.classList.remove('show');
            }, 2000);
        });
    });
}

function showUnauthorizedModal() {
    const contactEmail = appConfig.contact_email;
    
    if (contactEmail) {
        const emailLink = document.getElementById('contact-email-link');
        emailLink.textContent = contactEmail;
        emailLink.href = `mailto:${contactEmail}`;
        document.getElementById('contact-email-sentence').classList.remove('hidden');
    }
    
    const modal = document.getElementById('error-modal');
    modal.classList.remove('hidden');
    
    document.getElementById('close-modal-btn').addEventListener('click', () => {
        modal.classList.add('hidden');
    });
}

function initCookieConsent() {
    const consent = localStorage.getItem('ots_cookie_consent');
    if (!consent) {
        const banner = document.getElementById('cookie-banner');
        banner.classList.remove('hidden');
        setTimeout(() => banner.classList.add('show'), 50);

        document.getElementById('cookie-accept-all').addEventListener('click', () => {
            localStorage.setItem('ots_cookie_consent', JSON.stringify({ tracking: true }));
            banner.classList.remove('show');
            setTimeout(() => banner.classList.add('hidden'), 500);
            loadAnalytics();
        });

        document.getElementById('cookie-essential').addEventListener('click', () => {
            localStorage.setItem('ots_cookie_consent', JSON.stringify({ tracking: false }));
            banner.classList.remove('show');
            setTimeout(() => banner.classList.add('hidden'), 500);
        });
    } else {
        const parsed = JSON.parse(consent);
        if (parsed.tracking) {
            loadAnalytics();
        }
    }
}

function loadAnalytics() {
    if (!appConfig.google_tag_id) return;
    if (document.getElementById('ga-script')) return;
    
    const script = document.createElement('script');
    script.id = 'ga-script';
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${appConfig.google_tag_id}`;
    document.head.appendChild(script);

    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', appConfig.google_tag_id);
}
