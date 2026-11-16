// Espera a que el HTML esté disponible antes de buscar elementos y conectar la interfaz.
document.addEventListener('DOMContentLoaded', () => {

    /* ======================================================
       1. LÓGICA DE PESTAÑAS (8 MÓDULOS)
       ====================================================== */
    // Relaciona cada botón de navegación con el panel que debe mostrar.
    const tabs = {
        url: { btn: document.getElementById('btnTabUrl'), content: document.getElementById('tabUrlContent') },
        file: { btn: document.getElementById('btnTabFile'), content: document.getElementById('tabFileContent') },
        email: { btn: document.getElementById('btnTabEmail'), content: document.getElementById('tabEmailContent') },
        gen: { btn: document.getElementById('btnTabGen'), content: document.getElementById('tabGenContent') },
        val: { btn: document.getElementById('btnTabVal'), content: document.getElementById('tabValContent') },
        history: { btn: document.getElementById('btnTabHistory'), content: document.getElementById('tabHistoryContent') },
        glossary: { btn: document.getElementById('btnTabGlossary'), content: document.getElementById('tabGlossaryContent') },
        auth: { btn: document.getElementById('btnTabAuth'), content: document.getElementById('tabAuthContent') }
    };

    // Activa una pestaña, oculta las demás y actualiza las vistas que dependen de ella.
    function switchTab(activeKey) {
        Object.keys(tabs).forEach(key => {
            if (tabs[key].btn && tabs[key].content) {
                if (key === activeKey) {
                    tabs[key].btn.classList.add('active');
                    tabs[key].content.classList.remove('hidden');
                } else {
                    tabs[key].btn.classList.remove('active');
                    tabs[key].content.classList.add('hidden');
                }
            }
        });

        // Ocultar el cuadro de resultados global si no estás en URL o Archivo
        const resultsWrapper = document.getElementById('globalScanResultsWrapper');
        if (resultsWrapper) {
            if (activeKey === 'url' || activeKey === 'file') {
                resultsWrapper.classList.remove('hidden');
            } else {
                resultsWrapper.classList.add('hidden');
            }
        }

        // Si entra a historial, renderizarlo dinámicamente
        if (activeKey === 'history') renderHistory();
    }

    Object.keys(tabs).forEach(key => {
        if (tabs[key].btn) {
            tabs[key].btn.addEventListener('click', () => switchTab(key));
        }
    });

    // Usa el servidor API configurado o selecciona uno local o publicado por defecto.
    const pluginApiBase = window.CYBERSCAN_PLUGIN_API_BASE || (
        window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://localhost:3000/api/plugin'
            : 'https://infortech.onrender.com/api/plugin'
    );
    const authApiBase = pluginApiBase.replace(/\/api\/plugin\/?$/, '/api/auth');
    const scanApiBase = pluginApiBase.replace(/\/api\/plugin\/?$/, '');
    const authTokenKey = 'cyberscan_auth_token';

    // Centraliza las peticiones de autenticación y adjunta el token de sesión actual.
    async function authRequest(path, { method = 'GET', body } = {}) {
        const headers = {};
        const options = { method, headers };
        const token = localStorage.getItem(authTokenKey);
        if (token) headers.Authorization = `Bearer ${token}`;
        if (body instanceof FormData) {
            options.body = body;
        } else if (body !== undefined) {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }

        const response = await fetch(`${authApiBase}${path}`, options);
        const data = response.status === 204 ? {} : await response.json().catch(() => ({}));
        if (!response.ok) {
            const error = new Error(data.error || `Error HTTP ${response.status}`);
            error.status = response.status;
            throw error;
        }
        return data;
    }

    /* ======================================================
       2. MÓDULO DE AUTENTICACIÓN Y CONTROL DE ACCESO
       ====================================================== */
    // Referencias a las áreas, formularios y elementos que forman la interfaz de cuenta.
    const authSection = document.getElementById('authSection');
    const mainAppContent = document.getElementById('mainAppContent');

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const forgotForm = document.getElementById('forgotForm');

    const toRegister = document.getElementById('toRegister');
    const toLoginFromReg = document.getElementById('toLoginFromReg');
    const toForgot = document.getElementById('toForgot');
    const toLoginFromForgot = document.getElementById('toLoginFromForgot');

    const authMessage = document.getElementById('authMessage');
    const profileName = document.getElementById('profileName');
    const profileEmail = document.getElementById('profileEmail');
    const profileImage = document.getElementById('profileImage');
    const profileIcon = document.getElementById('profileIcon');
    const avatarInput = document.getElementById('avatarInput');
    const navAvatar = document.getElementById('navAvatar');
    const navUserText = document.getElementById('navUserText');
    const logoutBtn = document.getElementById('logoutBtn');

    // Transiciones entre formularios
    if (toRegister) {
        toRegister.addEventListener('click', (e) => {
            e.preventDefault();
            loginForm.classList.add('hidden');
            forgotForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
            hideAuthMsg();
        });
    }

    if (toLoginFromReg) {
        toLoginFromReg.addEventListener('click', (e) => {
            e.preventDefault();
            registerForm.classList.add('hidden');
            forgotForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            hideAuthMsg();
        });
    }

    if (toForgot) {
        toForgot.addEventListener('click', (e) => {
            e.preventDefault();
            loginForm.classList.add('hidden');
            registerForm.classList.add('hidden');
            forgotForm.classList.remove('hidden');
            hideAuthMsg();
        });
    }

    if (toLoginFromForgot) {
        toLoginFromForgot.addEventListener('click', (e) => {
            e.preventDefault();
            forgotForm.classList.add('hidden');
            registerForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            hideAuthMsg();
        });
    }

    // Presenta mensajes de éxito o error junto a los formularios de cuenta.
    function showAuthMsg(msg, isError = false) {
        authMessage.textContent = msg;
        authMessage.className = `text-center text-xs mt-3 ${isError ? 'text-red-400' : 'text-green-400'}`;
        authMessage.classList.remove('hidden');
    }

    // Oculta el mensaje anterior al cambiar de formulario o limpiar el estado.
    function hideAuthMsg() {
        authMessage.classList.add('hidden');
    }

    // Crea la cuenta en el servidor y conserva únicamente el token de sesión en el navegador.
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('regUser').value.trim();
            const email = document.getElementById('regEmail').value.trim().toLowerCase();
            const password = document.getElementById('regPass').value;
            const submitButton = registerForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            showAuthMsg('Creando cuenta...');
            try {
                const result = await authRequest('/register', {
                    method: 'POST',
                    body: { username, email, password },
                });
                localStorage.setItem(authTokenKey, result.token);
                registerForm.reset();
                await checkSession();
            } catch (error) {
                showAuthMsg(error.message, true);
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    // Valida las credenciales en el servidor y guarda el token de la sesión creada.
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value.trim().toLowerCase();
            const password = document.getElementById('loginPass').value;
            const submitButton = loginForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            showAuthMsg('Iniciando sesión...');
            try {
                const result = await authRequest('/login', {
                    method: 'POST',
                    body: { email, password },
                });
                localStorage.setItem(authTokenKey, result.token);
                loginForm.reset();
                await checkSession();
            } catch (error) {
                showAuthMsg(error.message, true);
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    // Sube la foto al servidor para que quede asociada a la cuenta en la base de datos.
    if (avatarInput) {
        avatarInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            if (file.size > 2 * 1024 * 1024) {
                alert("La imagen es muy grande. Elige una menor a 2MB.");
                return;
            }

            const formData = new FormData();
            formData.append('avatar', file);
            try {
                const result = await authRequest('/profile/avatar', { method: 'PUT', body: formData });
                updateProfileUI(result.user);
            } catch (error) {
                alert(`No se pudo guardar la foto de perfil: ${error.message}`);
            } finally {
                avatarInput.value = '';
            }
        });
    }

    // Sincroniza el nombre, correo y avatar en la pestaña de cuenta y la navegación.
    function updateProfileUI(session) {
        profileName.textContent = session.user;
        profileEmail.textContent = session.email;
        navUserText.textContent = session.user;

        if (session.avatar) {
            profileImage.src = session.avatar;
            profileImage.classList.remove('hidden');
            profileIcon.classList.add('hidden');

            navAvatar.src = session.avatar;
            navAvatar.classList.remove('hidden');
        } else {
            profileImage.classList.add('hidden');
            profileIcon.classList.remove('hidden');

            navAvatar.classList.add('hidden');
        }
    }

    // Revoca la sesión en MySQL y elimina el token de este navegador.
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            let logoutError;
            try {
                await authRequest('/session', { method: 'DELETE' });
            } catch (error) {
                logoutError = error;
            } finally {
                localStorage.removeItem(authTokenKey);
            }
            await checkSession();
            if (logoutError) {
                showAuthMsg(`Se cerró la sesión en este navegador, pero el servidor no pudo revocarla: ${logoutError.message}`, true);
            }
        });
    }

    // Consulta al servidor para validar el token y recuperar el perfil persistido.
    async function checkSession() {
        if (!localStorage.getItem(authTokenKey)) {
            authSection.classList.remove('hidden');
            mainAppContent.classList.add('hidden');
            mainAppContent.classList.remove('flex');
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
            forgotForm.classList.add('hidden');
            hideAuthMsg();
            return;
        }

        try {
            const result = await authRequest('/me');
            authSection.classList.add('hidden');
            mainAppContent.classList.remove('hidden');
            mainAppContent.classList.add('flex');
            updateProfileUI(result.user);
            switchTab('url'); // Abrir pestaña por defecto al entrar
        } catch (error) {
            if (error.status === 401) {
                localStorage.removeItem(authTokenKey);
                authSection.classList.remove('hidden');
                mainAppContent.classList.add('hidden');
                mainAppContent.classList.remove('flex');
                loginForm.classList.remove('hidden');
                registerForm.classList.add('hidden');
                forgotForm.classList.add('hidden');
                showAuthMsg(error.message, true);
                return;
            }
            authSection.classList.remove('hidden');
            mainAppContent.classList.add('hidden');
            mainAppContent.classList.remove('flex');
            showAuthMsg(`No se pudo validar la sesión con el servidor: ${error.message}`, true);
        }
    }

    checkSession();

    /* ======================================================
       3. HISTORIAL LOCAL (LocalStorage)
       ====================================================== */
    // Añade el análisis más reciente al historial local y conserva como máximo 20.
    function saveToHistory(tipo, detalle, estado) {
        let history = JSON.parse(localStorage.getItem('infortech_history')) || [];
        history.unshift({
            tipo,
            detalle,
            estado,
            fecha: new Date().toLocaleDateString() + ' ' + new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})
        });
        if (history.length > 20) history.pop();
        localStorage.setItem('infortech_history', JSON.stringify(history));
    }

    // Codifica caracteres HTML para que los datos del historial se muestren como texto.
    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, character => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
        })[character]);
    }

    // Renderiza el historial guardado en LocalStorage dentro de su panel.
    function renderHistory() {
        const container = document.getElementById('historyListContainer');
        const history = JSON.parse(localStorage.getItem('infortech_history')) || [];
        
        if (history.length === 0) {
            container.innerHTML = '<p class="text-gray-500 text-center">No hay análisis registrados todavía.</p>';
            return;
        }

        container.innerHTML = history.map(item => `
            <div class="bg-gray-800 p-2 rounded flex justify-between items-center border-l-4 ${item.estado === 'safe' ? 'border-green-500' : 'border-red-500'}">
                <div>
                    <span class="font-bold text-white uppercase text-xs bg-gray-700 px-1.5 py-0.5 rounded">${escapeHtml(item.tipo)}</span>
                    <p class="text-gray-300 text-sm mt-1 truncate max-w-[250px] md:max-w-md">${escapeHtml(item.detalle)}</p>
                </div>
                <span class="text-xs text-gray-400 whitespace-nowrap">${escapeHtml(item.fecha)}</span>
            </div>
        `).join('');
    }

    const clearHistoryBtn = document.getElementById('clearHistoryBtn');
    // Elimina solamente el historial local cuando el usuario solicita limpiarlo.
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', () => {
            localStorage.removeItem('infortech_history');
            renderHistory();
        });
    }

    /* ======================================================
       4. ANALIZADOR DE URL (VirusTotal + Proxy)
       ====================================================== */
    const urlInput = document.getElementById('urlInput');
    const analyzeButton = document.getElementById('analyzeButton');
    const analyzerStatus = document.getElementById('analyzerStatus');
    const resultsContainer = document.getElementById('resultsContainer');

    // Consulta VirusTotal y, en paralelo, intenta obtener el HTML de la URL para mostrar metadatos.
    if (analyzeButton) {
        analyzeButton.addEventListener('click', async () => {
            let url = urlInput.value.trim();
            if (!url) return alert("Por favor, ingresa una URL.");
            if (!url.startsWith('http')) { url = 'https://' + url; urlInput.value = url; }

            analyzerStatus.textContent = 'Analizando URL... (puede tardar hasta 90 segundos)';
            analyzerStatus.className = 'text-lg mt-4 h-6 text-yellow-400';
            analyzeButton.disabled = true;
            analyzeButton.classList.add('loading');
            resultsContainer.innerHTML = '<p class="text-center text-gray-400">Procesando...</p>';

            // Limita el tiempo de espera del análisis del backend para evitar una espera indefinida.
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 90000);

            try {
                // allSettled permite mostrar el resultado disponible aunque una de las dos consultas falle.
                const [vtResult, htmlResult] = await Promise.allSettled([
                    fetch(`${scanApiBase}/analizar?url=${encodeURIComponent(url)}`, { signal: controller.signal })
                        .then(async res => {
                            const data = await res.json();
                            if (res.status === 202) throw new Error(data.message || 'El análisis continúa en proceso.');
                            if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
                            return data;
                        }),
                    fetch(`https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`)
                        .then(res => res.text())
                ]);
                clearTimeout(timeoutId);

                renderResult(vtResult, htmlResult);
                
                if (vtResult.status === 'fulfilled' && vtResult.value.stats) {
                    const isSafe = vtResult.value.stats.malicious === 0 && vtResult.value.stats.suspicious === 0;
                    saveToHistory('URL', url, isSafe ? 'safe' : 'danger');
                } else if (vtResult.status === 'rejected') {
                    analyzerStatus.textContent = `No se pudo completar o guardar el análisis: ${vtResult.reason.message}`;
                    analyzerStatus.className = 'text-lg mt-4 h-6 text-red-400';
                } else {
                    analyzerStatus.textContent = 'El análisis no devolvió resultados para guardar.';
                    analyzerStatus.className = 'text-lg mt-4 h-6 text-red-400';
                }
            } catch (error) {
                analyzerStatus.textContent = 'Error crítico de conexión (Timeout).';
                analyzerStatus.className = 'text-lg mt-4 h-6 text-red-400';
            } finally {
                analyzeButton.disabled = false; 
                analyzeButton.classList.remove('loading');
            }
        });
    }

    /* ======================================================
       5. ANALIZADOR DE ARCHIVO
       ====================================================== */
    const fileInput = document.getElementById('fileInput');
    const analyzeFileButton = document.getElementById('analyzeFileButton');

    // Envía el archivo seleccionado al backend y muestra el resultado de VirusTotal.
    if (analyzeFileButton) {
        analyzeFileButton.addEventListener('click', async () => {
            if (!fileInput.files[0]) return alert("Selecciona un archivo primero.");
            const file = fileInput.files[0];

            const formData = new FormData();
            formData.append('file', file);

            analyzerStatus.textContent = 'Subiendo y Analizando Archivo...';
            analyzerStatus.className = 'text-lg mt-4 h-6 text-yellow-400';
            analyzeFileButton.disabled = true;
            analyzeFileButton.classList.add('loading');
            resultsContainer.innerHTML = '<p class="text-center text-gray-400">Subiendo a VirusTotal...</p>';

            try {
                const response = await fetch(`${scanApiBase}/analizar-archivo`, {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.status === 202) throw new Error(data.message || 'El análisis continúa en proceso.');
                if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
                
                if (data.stats) {
                    renderResult({ status: 'fulfilled', value: data }, null);
                    const isSafe = data.stats.malicious === 0 && data.stats.suspicious === 0;
                    saveToHistory('Archivo', file.name, isSafe ? 'safe' : 'danger');
                } else {
                    throw new Error(data.error || "Error desconocido del servidor");
                }
            } catch (error) {
                analyzerStatus.textContent = 'Error al analizar archivo.';
                analyzerStatus.className = 'text-lg mt-4 h-6 text-red-400';
                resultsContainer.innerHTML = `<p class="text-red-400">Detalle: ${error.message}</p>`;
            } finally {
                analyzeFileButton.disabled = false; 
                analyzeFileButton.classList.remove('loading');
            }
        });
    }

    // Descarga el informe del plugin y comunica errores de API sin cambiar de página.
    const downloadReportPdfButton = document.getElementById('downloadReportPdfButton');
    if (downloadReportPdfButton) {
        downloadReportPdfButton.addEventListener('click', async () => {
            const originalText = downloadReportPdfButton.textContent;
            downloadReportPdfButton.disabled = true;
            downloadReportPdfButton.textContent = 'Generando informe...';
            try {
                const response = await fetch(`${pluginApiBase}/report/pdf`);
                if (!response.ok) {
                    const error = await response.json().catch(() => ({}));
                    throw new Error(error.error || `Error HTTP ${response.status}`);
                }
                const pdfBlob = await response.blob();
                const downloadUrl = URL.createObjectURL(pdfBlob);
                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = 'Reporte_Ciberseguridad.pdf';
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(downloadUrl);
            } catch (error) {
                alert(`No se pudo descargar el reporte: ${error.message}`);
            } finally {
                downloadReportPdfButton.disabled = false;
                downloadReportPdfButton.textContent = originalText;
            }
        });
    }

    // Construye las tarjetas de resultados del escaneo y del contenido HTML, si están disponibles.
    function renderResult(vt, html) {
        analyzerStatus.textContent = 'Completado';
        analyzerStatus.className = 'text-lg mt-4 h-6 text-green-400';
        let htmlContent = '';

        if (vt && vt.status === 'fulfilled') {
            const data = vt.value;
            if (data.stats) {
                const isSafe = data.stats.malicious === 0 && data.stats.suspicious === 0;
                let detectionsHtml = '';
                if (data.results) {
                    const threats = Object.values(data.results).filter(r => r.category === 'malicious' || r.category === 'suspicious');
                    if (threats.length > 0) {
                        detectionsHtml = `
                        <div class="mt-4 pt-2 border-t border-gray-600">
                            <h4 class="font-bold text-white mb-2">Detalles de Amenazas:</h4>
                            <ul class="text-sm max-h-40 overflow-y-auto bg-gray-900 p-2 rounded">
                                ${threats.map(t => `<li class="mb-1"><span class="text-red-400 font-bold">${t.engine_name}:</span> <span class="text-gray-300">${t.result}</span></li>`).join('')}
                            </ul>
                        </div>`;
                    } else {
                         detectionsHtml = `<div class="mt-4 pt-2 border-t border-gray-600"><p class="text-green-400 text-sm">Ningún motor detectó amenazas específicas.</p></div>`;
                    }
                }

                htmlContent += `
                <div class="bg-gray-800 p-4 rounded-lg border ${isSafe ? 'border-green-500' : 'border-red-500'} mb-4">
                    <h3 class="text-xl font-bold mb-4 text-white">🛡️ Reporte de Seguridad</h3>
                    <div class="grid grid-cols-3 gap-2 text-center mb-2">
                        <div><p class="text-red-400 font-bold">Malignos</p><p class="text-2xl">${data.stats.malicious}</p></div>
                        <div><p class="text-yellow-400 font-bold">Sospechosos</p><p class="text-2xl">${data.stats.suspicious}</p></div>
                        <div><p class="text-green-400 font-bold">Seguros</p><p class="text-2xl">${data.stats.harmless}</p></div>
                    </div>
                    ${detectionsHtml}
                </div>`;
            } else {
                htmlContent += `<p class="text-red-400">Error VT: ${data.error || 'Sin datos'}</p>`;
            }
        }

        if (html && html.status === 'fulfilled') {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html.value, 'text/html');
            const title = doc.querySelector('title')?.textContent || 'Sin título';
            const h1 = doc.querySelector('h1')?.textContent || 'Sin H1';
            htmlContent += `
                <div class="bg-gray-800 p-4 rounded-lg border border-blue-500">
                    <h3 class="text-xl font-bold mb-2 text-white">📄 Análisis de Contenido</h3>
                    <p class="text-gray-300"><strong>Título:</strong> ${title}</p>
                    <p class="text-gray-300"><strong>Encabezado H1:</strong> ${h1}</p>
                </div>`;
        }

        resultsContainer.innerHTML = htmlContent || '<p class="text-gray-400 text-center">No hay resultados.</p>';
    }

    /* ======================================================
       6. DETECCIÓN DE FILTRACIONES (EMAIL)
       ====================================================== */
    const breachBtn = document.getElementById("breach-btn");
    const breachEmailInput = document.getElementById("breach-email");
    const breachResult = document.getElementById("breach-result");

    // Consulta al backend si el correo aparece en filtraciones y actualiza el historial local.
    if (breachBtn) {
        breachBtn.addEventListener("click", async () => {
            const email = breachEmailInput.value.trim();
            if (!email || !email.includes("@")) return alert("Ingresa un correo válido.");

            breachResult.classList.remove("hidden");
            breachResult.className = "mt-4 p-3 rounded-lg text-sm bg-gray-700 text-white";
            breachResult.textContent = "Verificando bases de datos...";
            breachBtn.disabled = true;
            try {
                const response = await fetch(`${pluginApiBase}/scan-email`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email }),
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);

                if (data.breachCount) {
                    breachResult.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-500 text-red-300";
                    breachResult.textContent = `Se encontraron ${data.breachCount} filtraciones: ${data.breaches.map(item => item.name).join(', ')}. Consulta y resultado guardados en la base de datos.`;
                    saveToHistory('Filtración', email, 'danger');
                } else {
                    breachResult.className = "mt-4 p-3 rounded-lg text-sm bg-green-900/50 border border-green-500 text-green-300";
                    breachResult.textContent = 'HIBP no encontró este correo en las filtraciones consultadas. El resultado se guardó en la base de datos.';
                    saveToHistory('Filtración', email, 'safe');
                }
            } catch (error) {
                breachResult.className = "mt-4 p-3 rounded-lg text-sm bg-red-900/50 border border-red-500 text-red-300";
                breachResult.textContent = error.message;
            } finally {
                breachBtn.disabled = false;
            }
        });
    }

    /* ======================================================
       7. GENERADOR DE CONTRASEÑAS
       ====================================================== */
    const genPasswordOutput = document.getElementById('genPasswordOutput');
    const genLength = document.getElementById('genLength');
    const lengthVal = document.getElementById('lengthVal');
    const genSymbols = document.getElementById('genSymbols');
    const genNumbers = document.getElementById('genNumbers');
    const generatePassBtn = document.getElementById('generatePassBtn');
    const copyGenPass = document.getElementById('copyGenPass');

    // Mantiene visible el valor seleccionado para la longitud de la contraseña.
    if (genLength) {
        genLength.addEventListener('input', (e) => lengthVal.textContent = e.target.value);
    }

    // Genera una contraseña aleatoria según longitud y conjuntos de caracteres elegidos.
    function generatePassword() {
        const length = parseInt(genLength.value);
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (genNumbers.checked) chars += "0123456789";
        if (genSymbols.checked) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

        let password = "";
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        genPasswordOutput.value = password;
    }

    if (generatePassBtn) {
        generatePassBtn.addEventListener('click', generatePassword);
        generatePassword();
    }

    // Copia el resultado generado al portapapeles y ofrece una confirmación temporal.
    if (copyGenPass) {
        copyGenPass.addEventListener('click', () => {
            if (!genPasswordOutput.value) return;
            navigator.clipboard.writeText(genPasswordOutput.value);
            copyGenPass.textContent = "¡Copiado!";
            setTimeout(() => copyGenPass.textContent = "Copiar", 1500);
        });
    }

    /* ======================================================
       8. VALIDADOR DE CONTRASEÑAS
       ====================================================== */
    const valPasswordInput = document.getElementById('valPasswordInput');
    const valStrengthBar = document.getElementById('valStrengthBar');
    const valStrengthText = document.getElementById('valStrengthText');

    // Evalúa la contraseña solo en el navegador y actualiza el indicador de fortaleza.
    if (valPasswordInput) {
        valPasswordInput.addEventListener('input', () => {
            const pass = valPasswordInput.value;
            if (!pass) {
                valStrengthBar.style.width = '0%';
                valStrengthBar.className = 'h-full transition-all duration-300 bg-red-500';
                valStrengthText.textContent = "Ingresa una clave para evaluar su seguridad.";
                return;
            }

            // Suma criterios simples de longitud y variedad; es una guía, no una auditoría criptográfica.
            let score = 0;
            if (pass.length >= 8) score++;
            if (pass.length >= 12) score++;
            if (/[0-9]/.test(pass)) score++;
            if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score++;
            if (/[^A-Za-z0-9]/.test(pass)) score++;

            if (score <= 2) {
                valStrengthBar.style.width = '33%';
                valStrengthBar.className = 'h-full transition-all duration-300 bg-red-500';
                valStrengthText.textContent = "⚠️ Contraseña Débil (Fácil de adivinar o romper por fuerza bruta).";
            } else if (score <= 4) {
                valStrengthBar.style.width = '66%';
                valStrengthBar.className = 'h-full transition-all duration-300 bg-yellow-500';
                valStrengthText.textContent = "⚡ Contraseña Moderada (Se recomienda agregar símbolos o más longitud).";
            } else {
                valStrengthBar.style.width = '100%';
                valStrengthBar.className = 'h-full transition-all duration-300 bg-green-500';
                valStrengthText.textContent = "🔒 Contraseña Fuerte y Segura.";
            }
        });
    }

});
