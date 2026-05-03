// script.js - ZeroPhish AI Landing Page

document.addEventListener('DOMContentLoaded', () => {
    console.log('ZeroPhish AI landing page loaded');

    // ── Navbar scroll effect ────────────────────────────
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 40);
    });

    // ── Smooth scroll for anchor links ──────────────────
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    // ── Detect scan type from content ──────────────────
    function detectType(content) {
        if (/^https?:\/\//i.test(content) || /^www\./i.test(content)) return 'URL';
        if (/@/.test(content) && /\.[a-z]{2,}$/i.test((content.split('@')[1] || ''))) return 'Email';
        return 'Message';
    }

    function scoreClass(score) {
        if (score > 65) return 'high-risk';
        if (score > 35) return 'suspicious';
        return 'safe';
    }

    // ── Hero Scan Button ────────────────────────────────
    const heroBtn = document.getElementById('hero-scan-btn');
    const heroInput = document.getElementById('hero-scan-input');
    const heroResult = document.getElementById('hero-scan-result');

    if (heroBtn && heroInput) {
        heroBtn.addEventListener('click', async () => {
            const content = heroInput.value.trim();
            if (!content) { heroInput.focus(); return; }

            heroBtn.disabled = true;
            heroBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...';
            heroResult.style.display = 'none';

            try {
                const token = localStorage.getItem('zp_token');
                const headers = { 'Content-Type': 'application/json' };
                if (token) headers['Authorization'] = `Bearer ${token}`;

                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({ content, scan_type: detectType(content) })
                });
                if (res.status === 401) {
                    heroResult.innerHTML = `<div class="hero-result-box error"><i class="fa-solid fa-lock"></i> Please <a href="/login" style="color:var(--primary); text-decoration:underline; font-weight:600;">log in</a> to use the scanner.</div>`;
                    heroResult.style.display = 'block';
                    return;
                }

                const data = await res.json();

                if (!res.ok) {
                    heroResult.innerHTML = `<div class="hero-result-box error"><i class="fa-solid fa-circle-xmark"></i> ${data.detail || 'Scan failed.'}</div>`;
                } else {
                    const cls = scoreClass(data.risk_score);
                    const icons = { 'High Risk': 'fa-shield-virus', 'Suspicious': 'fa-triangle-exclamation', 'Safe': 'fa-shield-check' };
                    const icon = icons[data.result] || 'fa-shield';
                    heroResult.innerHTML = `
                        <div class="hero-result-box ${cls}">
                            <div class="hres-left">
                                <i class="fa-solid ${icon}"></i>
                                <div>
                                    <strong>${data.result}</strong>
                                    <span>${data.details}</span>
                                </div>
                            </div>
                            <div class="hres-score">${data.risk_score}<small>/100</small></div>
                        </div>`;
                    heroInput.value = '';
                }
                heroResult.style.display = 'block';
            } catch (err) {
                heroResult.innerHTML = `<div class="hero-result-box error"><i class="fa-solid fa-wifi"></i> Network error. Please try again.</div>`;
                heroResult.style.display = 'block';
            } finally {
                heroBtn.disabled = false;
                heroBtn.innerHTML = 'Scan Now <i class="fa-solid fa-arrow-right"></i>';
            }
        });

        heroInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') heroBtn.click(); });
    }

    // ── Scroll-in animations ────────────────────────────
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, { threshold: 0.15 });

    document.querySelectorAll('.feature, .step, .trusted-logos span').forEach(el => {
        el.classList.add('fade-in-up');
        observer.observe(el);
    });
});
