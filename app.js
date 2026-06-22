// =====================================================================
// SYNCHRONOUS SHA-256 HELPER FOR SEGURIDAD HASH (RNF-INT-03)
// =====================================================================
function sha256(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var i, j;
    var result = '';
    var words = [];
    var asciiLength = ascii.length;
    var hash = [];
    var k = [];
    var primeCounter = 0;
    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = 1;
            }
            hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }
    ascii += '\x80';
    while (ascii.length % 64 - 56) ascii += '\x00';
    for (i = 0; i < ascii.length; i++) {
        j = ascii.charCodeAt(i);
        if (j >> 8) return; // ASCII only
        words[i >> 2] |= j << ((3 - i % 4) * 8);
    }
    words[words.length] = ((asciiLength * 8) / maxWord) | 0;
    words[words.length] = (asciiLength * 8);
    for (j = 0; j < words.length; ) {
        var w = words.slice(j, j += 16);
        var oldHash = hash.slice(0);
        for (i = 0; i < 64; i++) {
            var wItem = w[i];
            var temp1 = (wItem === undefined) ? (
                (wItem = w[i - 16] + (rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3)) + w[i - 7] + (rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10))) | 0
            ) : wItem;
            var temp2 = hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ((hash[4] & hash[5]) ^ (~hash[4] & hash[6])) + k[i] + temp1;
            var temp3 = (rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + ((hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]));
            hash = [(temp2 + temp3) | 0].concat(hash);
            hash[4] = (hash[4] + temp2) | 0;
            hash[7] = (hash[7] & maxWord) | 0;
        }
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }
    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? '0' : '') + b.toString(16);
        }
    }
    return result;
}

function parseDateStr(str) {
    if (!str) return new Date();
    const parts = str.split('/');
    if (parts.length === 3) {
        return new Date(parts[2], parts[1] - 1, parts[0]);
    }
    return new Date(str);
}

// =====================================================================
// MODELO DE DATOS Y BASE DE DATOS SIMULADA (PORTADO DE PYTHON)
// =====================================================================

class Producto {
    constructor(id_prod, nombre, precio, stock, categoria) {
        this.id_prod = id_prod;
        this.nombre = nombre;
        this.precio = precio;
        this.stock = stock;
        this.categoria = categoria; // 'Bebestibles' o 'Alimentos' (RF-08)
        this.version = 1; // Timestamp/Versión para bloqueo optimista (RBN-CONCURRENCIA)
    }

    get disponible() {
        return this.stock > 0 ? "Disponible" : "Agotado";
    }

    toDict() {
        return {
            id: this.id_prod,
            nombre: this.nombre,
            precio: this.precio,
            stock: this.stock,
            estado: this.disponible,
            categoria: this.categoria,
            version: this.version
        };
    }
}

class BaseDatosSimulada {
    constructor() {
        this.productos = {};
        this.usuarios = {};
        this.comandas = {};
        this.log_auditoria = [];
        this.cloud_backup = [];
    }

    inicializarDatosEjemplo() {
        // RNF-INT-03: Contraseñas seguras procesadas con Hash
        this.usuarios["admin01"] = { rol: "Administrador", pwd_hash: sha256("admin123"), intentos: 0 };
        this.usuarios["gerente01"] = { rol: "Gerente", pwd_hash: sha256("gerente123"), intentos: 0 };
        this.usuarios["garzon01"] = { rol: "Garzón", pwd_hash: sha256("garzon123"), intentos: 0 };

        // Inicialización de catálogo diario
        this.productos["P001"] = new Producto("P001", "Espresso", 1800, 15, "Bebestibles");
        this.productos["P002"] = new Producto("P002", "Sándwich de Jamón Queso", 3500, 1, "Alimentos");
        this.productos["P003"] = new Producto("P003", "Muffin de Arándano", 2200, 0, "Alimentos");
    }
}

// =====================================================================
// SISTEMA MOZ BACKEND LOGIC (PORTADO DE PYTHON)
// =====================================================================

class SistemaMoz {
    constructor(db) {
        this.db = db;
    }

    // --- CONTROL DE ACCESO ---
    autenticarUsuario(usuario_id, password_plano) {
        if (!(usuario_id in this.db.usuarios)) {
            return null;
        }

        const userData = this.db.usuarios[usuario_id];

        // Excepción: Control de bloqueo por intentos
        if (userData.intentos >= 5) {
            throw new Error("Cuenta bloqueada temporalmente por exceso de intentos fallidos (Seguridad).");
        }

        const hashIngresado = sha256(password_plano);
        if (userData.pwd_hash === hashIngresado) {
            userData.intentos = 0;
            return { usuario: usuario_id, rol: userData.rol };
        } else {
            userData.intentos += 1;
            return null;
        }
    }

    // --- RF-01: CONSULTA VISUAL DE CATÁLOGO EN TIEMPO REAL ---
    obtenerCatalogoMovil() {
        const inicio = performance.now();
        const catalogo = Object.values(this.db.productos).map(prod => prod.toDict());
        const duracion = (performance.now() - inicio) / 1000;
        
        // RNF-INT-01 / RF-01: Verificabilidad menor a 1 segundo
        if (duracion > 1.0) {
            throw new Error("Alerta: El refresco del catálogo superó el umbral de 1 segundo.");
        }
        return catalogo;
    }

    // --- RF-04 / RF-05 / RF-07: INTERFAZ DE GESTIÓN Y CONTROL DE CONCURRENCIA ---
    procesarComanda(tokenSesion, idMesa, itemsPedido, versionCliente) {
        if (tokenSesion.rol !== "Garzón" && tokenSesion.rol !== "Administrador") {
            return { exito: false, mensaje: "Operación permitida únicamente a Garzones autorizados." };
        }

        // Validación Transaccional Previa
        for (let item of itemsPedido) {
            const prodId = item.id_prod;
            const cant = item.cantidad;
            const nota = item.nota || "";

            // RF-04: Entrada de texto libre máximo 150 caracteres
            if (nota.length > 150) {
                return { exito: false, mensaje: `Error: La nota para el ítem ${prodId} excede el límite de 150 caracteres.` };
            }

            if (!(prodId in this.db.productos)) {
                return { exito: false, mensaje: `El producto ${prodId} no existe en el menú.` };
            }

            const productoReal = this.db.productos[prodId];

            // RBN-CONCURRENCIA: Control de Concurrencia Optimista (RF-05)
            if (versionCliente[prodId] !== productoReal.version) {
                return { 
                    exito: false, 
                    mensaje: `Conflicto de Concurrencia: El stock de '${productoReal.nombre}' cambió. Transacción rechazada.` 
                };
            }

            if (productoReal.stock < cant) {
                return { 
                    exito: false, 
                    mensaje: `Transacción rechazada: Stock insuficiente de '${productoReal.nombre}' (Stock actual: ${productoReal.stock}).` 
                };
            }
        }

        // Fase de Persistencia / Confirmación de Venta Efectiva (Aislamiento Transaccional)
        const timestamp = Math.floor(Date.now() / 1000);
        const comandaId = `COM-${timestamp}-${idMesa.replace(/\s+/g, '')}`;
        const detallesFinales = [];

        for (let item of itemsPedido) {
            const prodId = item.id_prod;
            const cant = item.cantidad;
            const productoReal = this.db.productos[prodId];

            // Decrementar stock y actualizar versión
            productoReal.stock -= cant;
            productoReal.version += 1;

            detallesFinales.append = detallesFinales.push({
                id_prod: prodId,
                nombre: productoReal.nombre,
                cantidad: cant,
                categoria: productoReal.categoria,
                nota: item.nota || ""
            });
        }

        const ahora = new Date();
        const fechaStr = `${String(ahora.getDate()).padStart(2, '0')}/${String(ahora.getMonth() + 1).padStart(2, '0')}/${ahora.getFullYear()}`;

        const nuevaComanda = {
            comanda_id: comandaId,
            mesa: idMesa,
            garzon: tokenSesion.usuario,
            fecha: fechaStr,
            items: detallesFinales
        };
        
        this.db.comandas[comandaId] = nuevaComanda;

        // RF-08: Enrutamiento Dinámico Automatizado a Tiqueteras de Barra y Cocina
        const logImpresion = this._enrutarTiqueterasImpresion(nuevaComanda);

        return { 
            exito: true, 
            mensaje: `Comanda ${comandaId} procesada exitosamente.`,
            logImpresion: logImpresion,
            comanda: nuevaComanda
        };
    }

    _enrutarTiqueterasImpresion(comanda) {
        let tieneBebestibles = false;
        let tieneAlimentos = false;
        const ticketBarra = [];
        const ticketCocina = [];

        for (let item of comanda.items) {
            if (item.categoria === "Bebestibles") {
                tieneBebestibles = true;
                ticketBarra.push(item);
            } else if (item.categoria === "Alimentos") {
                tieneAlimentos = true;
                ticketCocina.push(item);
            }
        }

        const resultado = [];
        if (tieneBebestibles) {
            resultado.push(`[Ticketera Barra IP 192.168.1.50] Imprimiendo Bebestibles para Mesa ${comanda.mesa}. Items: ${ticketBarra.map(i => `${i.cantidad}x ${i.nombre}`).join(', ')}`);
        }
        if (tieneAlimentos) {
            resultado.push(`[Ticketera Cocina IP 192.168.1.60] Imprimiendo Alimentos para Mesa ${comanda.mesa}. Items: ${ticketCocina.map(i => `${i.cantidad}x ${i.nombre}`).join(', ')}`);
        }
        return resultado;
    }

    // --- RF-02 & RF-03: RESTRICCIÓN DE PERFIL Y GENERADOR DE REPORTES HISTÓRICOS ---
    generarReporteVentasHistorico(tokenSesion, fechaInicio, fechaFin, garzonId = null) {
        const inicioReloj = performance.now();

        // RF-03: Restricción absoluta de Perfiles Financieros
        if (tokenSesion.rol !== "Administrador" && tokenSesion.rol !== "Gerente") {
            this.db.log_auditoria.push({
                evento: "ACCESO_DENEGADO_RF03", 
                usuario: tokenSesion.usuario, 
                fecha: new Date().toISOString()
            });
            throw new Error("Código Error HTTP 403 (Acceso Denegado): Rol operativo no tiene privilegios financieros.");
        }

        const ventasFiltradas = [];
        let totalAcumulado = 0;

        const dateInicio = parseDateStr(fechaInicio);
        const dateFin = parseDateStr(fechaFin);

        for (let comanda of Object.values(this.db.comandas)) {
            // Filtro por rango de fechas
            const dateCom = parseDateStr(comanda.fecha);
            if (dateCom >= dateInicio && dateCom <= dateFin) {
                if (garzonId && comanda.garzon !== garzonId) {
                    continue;
                }

                // Calcular montos
                for (let item of comanda.items) {
                    const prodId = item.id_prod;
                    const precioUn = this.db.productos[prodId].precio;
                    totalAcumulado += precioUn * item.cantidad;
                }
                ventasFiltradas.push(comanda);
            }
        }

        const timestamp = Math.floor(Date.now() / 1000);
        const reporteId = `REP-${timestamp}`;
        const reporteFinal = {
            reporte_id: reporteId,
            rango_fechas: `${fechaInicio} al ${fechaFin}`,
            transacciones_encontradas: ventasFiltradas.length,
            total_neto_chile: totalAcumulado,
            datos: ventasFiltradas
        };

        const duracion = (performance.now() - inicioReloj) / 1000;
        // RNF-INT-01: El tiempo total de procesamiento en el servidor no debe superar los 3.0 segundos
        if (duracion > 3.0) {
            throw new Error("Error de rendimiento RNF-INT-01: Tiempo de procesamiento de reporte excedido.");
        }

        return reporteFinal;
    }

    // --- RF-06: PURGA SEGURA CON RESPALDO AUTOMÁTICO EN LA NUBE ---
    eliminarYRespaldarReporte(tokenSesion, reporteAEliminar, opcionRespaldo) {
        if (tokenSesion.rol !== "Administrador") {
            throw new Error("Acción exclusiva del perfil Administrador.");
        }

        let logMsg = "";
        if (opcionRespaldo === "Eliminar y respaldar en la nube") {
            this.db.cloud_backup.push({
                backup_id: `CLOUD-${reporteAEliminar.reporte_id}`,
                fecha_respaldo: new Date().toISOString(),
                protocolo: "TLS 1.3",
                datos_empaquetados: reporteAEliminar
            });
            logMsg = "Informe respaldado exitosamente en repositorio Cloud via TLS 1.3 antes de ser eliminado de la DB local.";
        } else if (opcionRespaldo === "Eliminar permanentemente") {
            logMsg = "Informe purgado permanentemente de la base de datos sin copia externa.";
        } else {
            return "Operación cancelada por el usuario.";
        }

        // Registrar en auditoría
        this.db.log_auditoria.push({
            evento: "PURGA_REPORTE", 
            usuario: tokenSesion.usuario, 
            reporte_id: reporteAEliminar.reporte_id,
            fecha: new Date().toISOString()
        });

        return logMsg;
    }
}

// =====================================================================
// FRONTEND INTERACTION LOGIC
// =====================================================================

const db = new BaseDatosSimulada();
db.inicializarDatosEjemplo();
const sistema = new SistemaMoz(db);

let sesionActual = null;
let carrito = [];
let versionesClienteLocal = {}; // Map of prodId -> local version read from catalog

// DOM Elements
const loginScreen = document.getElementById("login-screen");
const dashboardScreen = document.getElementById("dashboard-screen");
const txtUsuario = document.getElementById("txt-usuario");
const txtPassword = document.getElementById("txt-password");
const btnLogin = document.getElementById("btn-login");
const errorLogin = document.getElementById("error-login");

const profileRol = document.getElementById("profile-rol");
const profileUsuario = document.getElementById("profile-usuario");
const avatarInicial = document.getElementById("avatar-inicial");
const btnLogout = document.getElementById("btn-logout");

const navCatalog = document.getElementById("nav-catalog");
const navOrder = document.getElementById("nav-order");
const navReports = document.getElementById("nav-reports");
const navConcurrency = document.getElementById("nav-concurrency");

const panelCatalog = document.getElementById("panel-catalog");
const panelOrder = document.getElementById("panel-order");
const panelReports = document.getElementById("panel-reports");
const panelConcurrency = document.getElementById("panel-concurrency");

const catalogGrid = document.getElementById("catalog-grid");
const menuSelector = document.getElementById("menu-selector");
const cartItemsContainer = document.getElementById("cart-items");
const cartTotalLabel = document.getElementById("cart-total-label");
const txtMesa = document.getElementById("txt-mesa");
const btnSendOrder = document.getElementById("btn-send-order");

const printTerminal = document.getElementById("print-terminal");
const auditTerminal = document.getElementById("audit-terminal");
const toast = document.getElementById("notification-toast");

// Concurrency Simulator Elements
const simProductSelect = document.getElementById("sim-product-select");
const simStockInput = document.getElementById("sim-stock-input");
const simBtnUpdate = document.getElementById("sim-btn-update");
const simTxtVersion = document.getElementById("sim-text-version");

// Reports Elements
const filterFechaInicio = document.getElementById("filter-fecha-inicio");
const filterFechaFin = document.getElementById("filter-fecha-fin");
const filterGarzon = document.getElementById("filter-garzon");
const btnGenReport = document.getElementById("btn-gen-report");
const reportDataPanel = document.getElementById("report-data-panel");
const reportAccessDenied = document.getElementById("report-access-denied");
const summaryTransacciones = document.getElementById("summary-transacciones");
const summaryTotal = document.getElementById("summary-total");
const summaryRango = document.getElementById("summary-rango");
const reportsTableBody = document.getElementById("reports-table-body");
const btnPurgeCloud = document.getElementById("btn-purge-cloud");
const btnPurgePerm = document.getElementById("btn-purge-perm");

let ultimoReporteGenerado = null;

// Initialization
document.addEventListener("DOMContentLoaded", () => {
    // Set default dates to today
    const hoy = new Date();
    const hoyStr = `${String(hoy.getDate()).padStart(2, '0')}/${String(hoy.getMonth() + 1).padStart(2, '0')}/${hoy.getFullYear()}`;
    filterFechaInicio.value = hoyStr;
    filterFechaFin.value = hoyStr;
});

// Toast Helper
function showToast(message, type = "success") {
    toast.textContent = message;
    toast.className = `toast-${type}`;
    toast.style.display = "flex";
    setTimeout(() => {
        toast.style.display = "none";
    }, 4000);
}

// Log Terminal Helpers
function addPrintLog(lines) {
    if (!Array.isArray(lines)) lines = [lines];
    lines.forEach(line => {
        const div = document.createElement("div");
        div.className = "terminal-line";
        div.textContent = `[${new Date().toLocaleTimeString()}] ${line}`;
        printTerminal.appendChild(div);
    });
    printTerminal.scrollTop = printTerminal.scrollHeight;
}

function addAuditLog(event, usuario, isSuccess = true, detail = "") {
    const div = document.createElement("div");
    div.className = "terminal-line";
    const statusClass = isSuccess ? "audit-success" : "audit-error";
    div.innerHTML = `[${new Date().toLocaleTimeString()}] <span class="audit-tag">${event}</span> | User: <strong>${usuario}</strong> | Status: <span class="${statusClass}">${isSuccess ? 'OK' : 'FAIL'}</span> ${detail}`;
    auditTerminal.appendChild(div);
    auditTerminal.scrollTop = auditTerminal.scrollHeight;
}

// =====================================================================
// AUTHENTICATION FLOW
// =====================================================================
btnLogin.addEventListener("click", () => {
    const username = txtUsuario.value.trim();
    const password = txtPassword.value;
    
    errorLogin.classList.add("d-none");

    try {
        const sesion = sistema.autenticarUsuario(username, password);
        if (sesion) {
            sesionActual = sesion;
            txtPassword.value = "";
            showToast(`Bienvenido ${sesion.usuario} (${sesion.rol})`, "success");
            addAuditLog("LOGIN", username, true, `Role: ${sesion.rol}`);
            
            // Show Dashboard
            loginScreen.classList.add("d-none");
            dashboardScreen.classList.remove("d-none");
            
            // Setup Profile Header
            profileUsuario.textContent = sesion.usuario;
            profileRol.textContent = sesion.rol;
            avatarInicial.textContent = sesion.usuario.substring(0,2).toUpperCase();

            // Refresh UI Views
            refreshCatalog();
            updateNavigationVisibility();
            switchPanel("catalog");
        } else {
            errorLogin.textContent = "Credenciales incorrectas. Intente nuevamente.";
            errorLogin.classList.remove("d-none");
            addAuditLog("LOGIN", username, false, "Invalid password");
        }
    } catch(err) {
        errorLogin.textContent = err.message;
        errorLogin.classList.remove("d-none");
        addAuditLog("LOGIN_BLOCKED", username, false, err.message);
    }
});

btnLogout.addEventListener("click", () => {
    addAuditLog("LOGOUT", sesionActual.usuario, true);
    sesionActual = null;
    carrito = [];
    ultimoReporteGenerado = null;
    dashboardScreen.classList.add("d-none");
    loginScreen.classList.remove("d-none");
    txtUsuario.value = "";
    txtPassword.value = "";
});

// Navigation Handling
const navItems = [navCatalog, navOrder, navReports, navConcurrency];
const panels = [panelCatalog, panelOrder, panelReports, panelConcurrency];

function switchPanel(panelName) {
    panels.forEach(p => p.classList.add("d-none"));
    navItems.forEach(n => n.classList.remove("active"));
    
    if (panelName === "catalog") {
        panelCatalog.classList.remove("d-none");
        navCatalog.classList.add("active");
        refreshCatalog();
    } else if (panelName === "order") {
        panelOrder.classList.remove("d-none");
        navOrder.classList.add("active");
        refreshOrderMenu();
    } else if (panelName === "reports") {
        panelReports.classList.remove("d-none");
        navReports.classList.add("active");
        renderReportsTab();
    } else if (panelName === "concurrency") {
        panelConcurrency.classList.remove("d-none");
        navConcurrency.classList.add("active");
        renderConcurrencyTab();
    }
}

navCatalog.addEventListener("click", () => switchPanel("catalog"));
navOrder.addEventListener("click", () => switchPanel("order"));
navReports.addEventListener("click", () => switchPanel("reports"));
navConcurrency.addEventListener("click", () => switchPanel("concurrency"));

function updateNavigationVisibility() {
    // Optional role hiding if needed. 
    // RF-03 security check is validated programmatically, but we keep sidebar visible so users can explicitly attempt access and trigger exceptions.
}

// =====================================================================
// RF-01: REAL-TIME CATALOG RENDER
// =====================================================================
function refreshCatalog() {
    try {
        const catalogo = sistema.obtenerCatalogoMovil();
        catalogGrid.innerHTML = "";
        
        catalogo.forEach(prod => {
            // Keep local version sync for ordering
            versionesClienteLocal[prod.id] = prod.version;

            const card = document.createElement("div");
            card.className = "product-card";
            
            const badgeClass = prod.stock > 0 ? "badge-disponible" : "badge-agotado";
            const estado = prod.stock > 0 ? "Disponible" : "Agotado";
            
            card.innerHTML = `
                <span class="product-badge ${badgeClass}">${estado}</span>
                <div class="product-name">${prod.nombre}</div>
                <div class="product-price">$${prod.precio.toLocaleString('es-CL')}</div>
                <div class="product-meta">
                    <span>Stock: ${prod.stock}</span>
                    <span>Versión: v${prod.version}</span>
                </div>
            `;
            catalogGrid.appendChild(card);
        });
    } catch(err) {
        showToast(err.message, "error");
    }
}

// =====================================================================
// RF-04 / RF-07 / RF-08: ORDER TAKING & PERSISTENCE
// =====================================================================
function refreshOrderMenu() {
    const catalogo = sistema.obtenerCatalogoMovil();
    menuSelector.innerHTML = "";
    
    catalogo.forEach(prod => {
        const itemDiv = document.createElement("div");
        itemDiv.className = "menu-selector-item";
        
        const isAgotado = prod.stock <= 0;
        
        itemDiv.innerHTML = `
            <div class="menu-item-info">
                <span class="menu-item-name">${prod.nombre} ${isAgotado ? '<span style="color:var(--danger); font-size:0.8rem;">(Agotado)</span>' : ''}</span>
                <span class="menu-item-price">$${prod.precio.toLocaleString('es-CL')} - Stock: ${prod.stock}</span>
            </div>
            <div class="menu-item-action">
                <input type="number" id="qty-${prod.id}" class="form-control qty-input" value="1" min="1" max="${prod.stock}" ${isAgotado ? 'disabled' : ''}>
                <button class="btn btn-secondary" style="padding: 0.4rem 0.8rem;" onclick="addToCart('${prod.id}')" ${isAgotado ? 'disabled' : ''}>Agregar</button>
            </div>
        `;
        menuSelector.appendChild(itemDiv);
    });
    
    renderCart();
}

window.addToCart = function(prodId) {
    const qtyInput = document.getElementById(`qty-${prodId}`);
    const cantidad = parseInt(qtyInput.value) || 1;
    
    const prod = db.productos[prodId];
    if (!prod) return;

    if (cantidad > prod.stock) {
        showToast(`Stock insuficiente para agregar ${cantidad} unidades.`, "error");
        return;
    }

    // Capture standard note prompt
    const nota = prompt(`Notas para ${prod.nombre} (Máximo 150 caracteres):`, "") || "";
    if (nota.length > 150) {
        showToast("La nota excede los 150 caracteres permitidos.", "error");
        return;
    }

    // Check if already in cart
    const existingIndex = carrito.findIndex(item => item.id_prod === prodId);
    if (existingIndex > -1) {
        if ((carrito[existingIndex].cantidad + cantidad) > prod.stock) {
            showToast("La cantidad total excede el stock actual del menú.", "error");
            return;
        }
        carrito[existingIndex].cantidad += cantidad;
        if (nota) {
            carrito[existingIndex].nota = (carrito[existingIndex].nota ? carrito[existingIndex].nota + ", " : "") + nota;
        }
    } else {
        carrito.push({
            id_prod: prodId,
            nombre: prod.nombre,
            precio: prod.precio,
            cantidad: cantidad,
            nota: nota
        });
    }

    showToast(`Agregado al carrito: ${prod.nombre}`);
    renderCart();
};

function renderCart() {
    cartItemsContainer.innerHTML = "";
    let total = 0;
    
    carrito.forEach((item, index) => {
        const itemPriceTotal = item.precio * item.cantidad;
        total += itemPriceTotal;
        
        const div = document.createElement("div");
        div.className = "cart-item";
        div.innerHTML = `
            <div class="cart-item-details">
                <span class="cart-item-title">${item.cantidad}x ${item.nombre}</span>
                ${item.nota ? `<span class="cart-item-note">Nota: ${item.nota}</span>` : ''}
            </div>
            <div class="flex-between" style="gap: 1rem;">
                <span class="cart-item-price">$${itemPriceTotal.toLocaleString('es-CL')}</span>
                <button class="cart-remove" onclick="removeFromCart(${index})">✕</button>
            </div>
        `;
        cartItemsContainer.appendChild(div);
    });

    cartTotalLabel.textContent = `$${total.toLocaleString('es-CL')} CLP`;
}

window.removeFromCart = function(index) {
    carrito.splice(index, 1);
    renderCart();
};

btnSendOrder.addEventListener("click", () => {
    if (carrito.length === 0) {
        showToast("El carrito está vacío.", "error");
        return;
    }
    
    const mesa = txtMesa.value.trim();
    if (!mesa) {
        showToast("Debe ingresar la Mesa correspondiente.", "error");
        return;
    }

    // Build the versions snapshot the client read
    const snapshotVersiones = {};
    carrito.forEach(item => {
        snapshotVersiones[item.id_prod] = versionesClienteLocal[item.id_prod];
    });

    const resultado = sistema.procesarComanda(sesionActual, mesa, carrito, snapshotVersiones);

    if (resultado.exito) {
        showToast(resultado.mensaje, "success");
        addAuditLog("PROCESAR_COMANDA", sesionActual.usuario, true, `Comanda: ${resultado.comanda.comanda_id}`);
        
        // Print physical output logs (RF-08)
        addPrintLog(resultado.logImpresion);

        // Reset
        carrito = [];
        txtMesa.value = "";
        refreshOrderMenu();
    } else {
        showToast(resultado.mensaje, "error");
        addAuditLog("PROCESAR_COMANDA", sesionActual.usuario, false, resultado.mensaje);
    }
});

// =====================================================================
// RF-05: CONCURRENCY SIMULATOR
// =====================================================================
function renderConcurrencyTab() {
    // Populate select
    simProductSelect.innerHTML = "";
    Object.values(db.productos).forEach(prod => {
        const opt = document.createElement("option");
        opt.value = prod.id_prod;
        opt.textContent = `${prod.nombre} (Stock: ${prod.stock}, v${prod.version})`;
        simProductSelect.appendChild(opt);
    });

    updateSimVersionText();
}

function updateSimVersionText() {
    const prodId = simProductSelect.value;
    const prod = db.productos[prodId];
    if (prod) {
        simTxtVersion.textContent = `Servidor actual: v${prod.version} | Tu versión de Garzón: v${versionesClienteLocal[prodId] || 1}`;
    }
}

simProductSelect.addEventListener("change", updateSimVersionText);

simBtnUpdate.addEventListener("click", () => {
    const prodId = simProductSelect.value;
    const nuevoStock = parseInt(simStockInput.value);
    
    if (isNaN(nuevoStock) || nuevoStock < 0) {
        showToast("Ingrese un stock válido.", "error");
        return;
    }

    const prod = db.productos[prodId];
    if (prod) {
        // Change stock and increment version on SERVER to simulate background modification
        prod.stock = nuevoStock;
        prod.version += 1;
        
        showToast(`Garzón B actualizó ${prod.nombre}. Stock: ${nuevoStock}, Versión: v${prod.version}.`, "warning");
        addAuditLog("SIMULACION_CONCURRENCIA", "Garzón B (Remoto)", true, `Updated stock of ${prod.id_prod} to ${nuevoStock}, bumped version to ${prod.version}`);
        
        renderConcurrencyTab();
    }
});

// =====================================================================
// RF-02 & RF-03: REPORTS MANAGEMENT
// =====================================================================
function renderReportsTab() {
    // Check access upfront
    if (sesionActual.rol !== "Administrador" && sesionActual.rol !== "Gerente") {
        reportDataPanel.classList.add("d-none");
        reportAccessDenied.classList.remove("d-none");
        
        // Log access violation inside database audits (RF-03 requirement)
        db.log_auditoria.push({
            evento: "ACCESO_DENEGADO_RF03", 
            usuario: sesionActual.usuario, 
            fecha: new Date().toISOString()
        });
        addAuditLog("REPORT_DENIED", sesionActual.usuario, false, "HTTP 403 - Missing Financial privileges");
        return;
    }

    reportAccessDenied.classList.add("d-none");
    reportDataPanel.classList.remove("d-none");

    // Populate Garzones filter list
    filterGarzon.innerHTML = '<option value="">Todos los Garzones</option>';
    Object.keys(db.usuarios).forEach(usr => {
        if (db.usuarios[usr].rol === "Garzón") {
            const opt = document.createElement("option");
            opt.value = usr;
            opt.textContent = usr;
            filterGarzon.appendChild(opt);
        }
    });

    // Toggle purge buttons: exclusive to admin (RF-06)
    if (sesionActual.rol === "Administrador") {
        btnPurgeCloud.disabled = false;
        btnPurgePerm.disabled = false;
    } else {
        btnPurgeCloud.disabled = true;
        btnPurgePerm.disabled = true;
    }
}

btnGenReport.addEventListener("click", () => {
    const fInicio = filterFechaInicio.value.trim();
    const fFin = filterFechaFin.value.trim();
    const garzonSel = filterGarzon.value || null;

    try {
        const rep = sistema.generarReporteVentasHistorico(sesionActual, fInicio, fFin, garzonSel);
        ultimoReporteGenerado = rep;

        // Render Summary
        summaryTransacciones.textContent = rep.transacciones_encontradas;
        summaryTotal.textContent = `$${rep.total_neto_chile.toLocaleString('es-CL')} CLP`;
        summaryRango.textContent = rep.rango_fechas;

        // Populate Table
        reportsTableBody.innerHTML = "";
        if (rep.datos.length === 0) {
            reportsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dark);">No se encontraron transacciones en este rango.</td></tr>`;
        } else {
            rep.datos.forEach(com => {
                const totalComanda = com.items.reduce((acc, curr) => acc + (db.productos[curr.id_prod].precio * curr.cantidad), 0);
                
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>${com.comanda_id}</strong></td>
                    <td>${com.fecha}</td>
                    <td>${com.mesa}</td>
                    <td>${com.garzon}</td>
                    <td>$${totalComanda.toLocaleString('es-CL')} CLP</td>
                `;
                reportsTableBody.appendChild(tr);
            });
        }

        showToast(`Reporte ${rep.reporte_id} generado.`);
        addAuditLog("GENERAR_REPORTE", sesionActual.usuario, true, `Reporte: ${rep.reporte_id}`);

    } catch(err) {
        showToast(err.message, "error");
        addAuditLog("GENERAR_REPORTE", sesionActual.usuario, false, err.message);
    }
});

// =====================================================================
// RF-06: SECURE CLOUD BACKUP & PURGE
// =====================================================================
function triggerPurge(opcion) {
    if (!ultimoReporteGenerado) {
        showToast("Primero genere un reporte para purgar.", "warning");
        return;
    }

    try {
        const logRespaldo = sistema.eliminarYRespaldarReporte(sesionActual, ultimoReporteGenerado, opcion);
        showToast("Purga completada.");
        
        // Log TLS 1.3 transfer to terminal
        if (opcion === "Eliminar y respaldar en la nube") {
            addPrintLog([
                `[Secure Channel] Handshaking TLS 1.3 connection...`,
                `[Secure Channel] Cipher Suite: TLS_AES_256_GCM_SHA384`,
                `[Secure Channel] Packaging Report ${ultimoReporteGenerado.reporte_id}...`,
                `[Secure Channel] Cloud Transfer OK. Backup ID: CLOUD-${ultimoReporteGenerado.reporte_id}`
            ]);
        }

        addAuditLog("PURGA_REPORTE", sesionActual.usuario, true, `Reporte: ${ultimoReporteGenerado.reporte_id} | Método: ${opcion}`);

        // Clean local database comandas in that range to simulate actual deletion
        const rep = ultimoReporteGenerado;
        rep.datos.forEach(com => {
            delete db.comandas[com.comanda_id];
        });

        // Reset report GUI view
        ultimoReporteGenerado = null;
        summaryTransacciones.textContent = "-";
        summaryTotal.textContent = "-";
        summaryRango.textContent = "-";
        reportsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dark);">Genere un reporte para visualizar.</td></tr>`;

    } catch(err) {
        showToast(err.message, "error");
        addAuditLog("PURGA_REPORTE", sesionActual.usuario, false, err.message);
    }
}

btnPurgeCloud.addEventListener("click", () => triggerPurge("Eliminar y respaldar en la nube"));
btnPurgePerm.addEventListener("click", () => triggerPurge("Eliminar permanentemente"));
