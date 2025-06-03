// Inicialización del editor CodeMirror
let editor = CodeMirror.fromTextArea(document.getElementById("editor"), {
    mode: "javascript",
    theme: "dracula",
    lineNumbers: true,
    autoCloseBrackets: true,
    matchBrackets: true,
    indentUnit: 4,
    tabSize: 4,
    lineWrapping: true,
    foldGutter: true,
    gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"],
    extraKeys: {
        "Ctrl-Space": "autocomplete"
    }
});

// Función para mostrar resultados
function mostrarResultado(resultado, esError = false) {
    const resultadoDiv = document.getElementById('resultado');
    resultadoDiv.innerHTML = '';
    resultadoDiv.className = esError ? 'error' : 'success';
    
    if (typeof resultado === 'object') {
        resultadoDiv.innerHTML = '<pre>' + JSON.stringify(resultado, null, 2) + '</pre>';
    } else {
        resultadoDiv.textContent = resultado;
    }
}

// Función para análisis léxico
async function analizarLexico() {
    const codigo = editor.getValue();
    try {
        const respuesta = await fetch('/analizar_lexico', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ codigo: codigo })
        });
        
        const resultado = await respuesta.json();
        mostrarResultado(resultado);
    } catch (error) {
        mostrarResultado('Error en el análisis léxico: ' + error.message, true);
    }
}

// Función para análisis sintáctico
async function analizarSintactico() {
    const codigo = editor.getValue();
    try {
        const respuesta = await fetch('/analizar_sintactico', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ codigo: codigo })
        });
        
        const resultado = await respuesta.json();
        mostrarResultado(resultado);
    } catch (error) {
        mostrarResultado('Error en el análisis sintáctico: ' + error.message, true);
    }
}

// Función para máquina de Turing
async function ejecutarTuring() {
    const entrada = editor.getValue();
    try {
        const respuesta = await fetch('/maquina_turing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ entrada: entrada })
        });
        
        const resultado = await respuesta.json();
        mostrarResultado(resultado);
    } catch (error) {
        mostrarResultado('Error en la máquina de Turing: ' + error.message, true);
    }
}

// Ajustar tamaño del editor al cargar y al redimensionar
function ajustarTamañoEditor() {
    const altura = window.innerHeight;
    editor.setSize(null, altura * 0.6);
}

window.addEventListener('load', ajustarTamañoEditor);
window.addEventListener('resize', ajustarTamañoEditor);

// Manejo de mensajes flash
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 3000);
    });

    // Animación de entrada para las tarjetas
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, 100 * index);
    });

    // Efecto de ripple para botones
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('click', function(e) {
            const ripple = document.createElement('div');
            ripple.classList.add('ripple');
            this.appendChild(ripple);

            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            ripple.style.width = ripple.style.height = size + 'px';

            const x = e.clientX - rect.left - size/2;
            const y = e.clientY - rect.top - size/2;
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';

            setTimeout(() => ripple.remove(), 600);
        });
    });

    // Animación para tablas
    const tableRows = document.querySelectorAll('tr');
    tableRows.forEach((row, index) => {
        row.style.opacity = '0';
        row.style.transform = 'translateX(-20px)';
        setTimeout(() => {
            row.style.transition = 'all 0.3s ease';
            row.style.opacity = '1';
            row.style.transform = 'translateX(0)';
        }, 50 * index);
    });

    // Efecto de hover para badges
    const badges = document.querySelectorAll('.badge');
    badges.forEach(badge => {
        badge.addEventListener('mouseover', function() {
            this.style.transform = 'scale(1.1) rotate(5deg)';
        });
        badge.addEventListener('mouseout', function() {
            this.style.transform = 'scale(1) rotate(0deg)';
        });
    });

    // Animación para el menú de navegación
    const navLinks = document.querySelectorAll('.nav-links a');
    navLinks.forEach((link, index) => {
        link.style.opacity = '0';
        link.style.transform = 'translateY(-10px)';
        setTimeout(() => {
            link.style.transition = 'all 0.3s ease';
            link.style.opacity = '1';
            link.style.transform = 'translateY(0)';
        }, 100 * index);
    });

    // Efecto de parallax suave para el fondo
    window.addEventListener('scroll', function() {
        const scrolled = window.pageYOffset;
        const parallaxElements = document.querySelectorAll('.parallax');
        parallaxElements.forEach(element => {
            const speed = element.dataset.speed || 0.5;
            element.style.transform = `translateY(${scrolled * speed}px)`;
        });
    });

    // Animación de carga para formularios
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.classList.add('loading');
                submitButton.disabled = true;
                
                // Restaurar el botón después de la animación
                setTimeout(() => {
                    submitButton.classList.remove('loading');
                    submitButton.disabled = false;
                }, 2000);
            }
        });
    });

    // Efecto de focus para campos de formulario
    const formInputs = document.querySelectorAll('.form-control');
    formInputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('input-focused');
        });
        input.addEventListener('blur', function() {
            if (!this.value) {
                this.parentElement.classList.remove('input-focused');
            }
        });
    });
});

// Validación de contraseña
function validarPassword(password) {
    const requirements = [
        { regex: /.{8,}/, index: 0 }, // Mínimo 8 caracteres
        { regex: /[A-Z]/, index: 1 }, // Al menos una mayúscula
        { regex: /[a-z]/, index: 2 }, // Al menos una minúscula
        { regex: /[0-9]/, index: 3 }, // Al menos un número
        { regex: /[^A-Za-z0-9]/, index: 4 } // Al menos un carácter especial
    ];

    const requirementsList = document.getElementById('password-requirements');
    if (!requirementsList) return true;

    let valid = true;
    requirements.forEach(requirement => {
        const li = requirementsList.children[requirement.index];
        const isValid = requirement.regex.test(password);
        if (li) {
            li.classList.toggle('valid', isValid);
            li.classList.toggle('invalid', !isValid);
        }
        valid = valid && isValid;
    });

    return valid;
}

// Validación del formulario de registro
if (document.getElementById('registroForm')) {
    const form = document.getElementById('registroForm');
    const passwordInput = document.getElementById('password');
    
    form.addEventListener('submit', function(e) {
        if (!validarPassword(passwordInput.value)) {
            e.preventDefault();
            alert('La contraseña debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas, números y caracteres especiales.');
        }
    });
}

// Confirmación para desactivar usuario
function confirmarDesactivacion(userId) {
    return confirm('¿Estás seguro de que deseas desactivar este usuario?');
}

// Función para previsualizar imagen de perfil
function previsualizarImagen(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        const preview = document.getElementById('previewImagen');
        
        reader.onload = function(e) {
            if (preview) {
                preview.style.opacity = '0';
                setTimeout(() => {
                    preview.src = e.target.result;
                    preview.style.transition = 'opacity 0.3s ease';
                    preview.style.opacity = '1';
                }, 300);
            }
        };
        
        reader.readAsDataURL(input.files[0]);
    }
}

// Función para confirmar acciones con animación
function confirmarAccion(mensaje, callback) {
    const modal = document.createElement('div');
    modal.className = 'modal fade-in';
    modal.innerHTML = `
        <div class="modal-content">
            <h3>${mensaje}</h3>
            <div class="modal-buttons">
                <button class="btn btn-secondary" onclick="this.parentElement.parentElement.parentElement.remove()">Cancelar</button>
                <button class="btn btn-warning" id="confirmar">Confirmar</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    document.getElementById('confirmar').addEventListener('click', function() {
        modal.classList.add('fade-out');
        setTimeout(() => {
            modal.remove();
            if (callback) callback();
        }, 300);
    });
} 