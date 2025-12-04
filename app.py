# auth.py - Sistema de autenticación seguro
import streamlit as st
import hashlib
import time
from datetime import datetime, timedelta
import json
import os

# ==============================================================================
#                   CONFIGURACIÓN DE ACCESO
# ==============================================================================

# Claves de acceso (en producción, esto debería estar en variables de entorno)
# Usuario: admin, Contraseña: admin123
USUARIOS_VALIDOS = {
    "admin": {
        "password_hash": "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",  # admin123
        "nombre": "Administrador",
        "rol": "admin",
        "email": "admin@laboratorio.com"
    },
    "usuario": {
        "password_hash": "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f",  # 123456
        "nombre": "Usuario General",
        "rol": "usuario",
        "email": "usuario@laboratorio.com"
    }
}

# Token de invitado temporal (válido por 24 horas)
TOKEN_INVITADO = "K0-INAA-2024-TEMP-ACCESS"
TOKEN_INVITADO_VALIDO_HASTA = datetime(2024, 12, 31)  # Cambiar según necesidad

# ==============================================================================
#                   FUNCIONES DE AUTENTICACIÓN
# ==============================================================================

def hash_password(password):
    """Encripta la contraseña usando SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verificar_credenciales(usuario, password):
    """Verifica si las credenciales son válidas"""
    if usuario in USUARIOS_VALIDOS:
        password_hash = hash_password(password)
        return password_hash == USUARIOS_VALIDOS[usuario]["password_hash"]
    return False

def verificar_token_invitado(token):
    """Verifica si el token de invitado es válido"""
    if token == TOKEN_INVITADO and datetime.now() <= TOKEN_INVITADO_VALIDO_HASTA:
        return True
    return False

def crear_sesion(usuario, es_invitado=False):
    """Crea una nueva sesión de usuario"""
    st.session_state.autenticado = True
    st.session_state.usuario = usuario
    st.session_state.es_invitado = es_invitado
    st.session_state.hora_inicio = datetime.now()
    
    if not es_invitado and usuario in USUARIOS_VALIDOS:
        st.session_state.nombre = USUARIOS_VALIDOS[usuario]["nombre"]
        st.session_state.rol = USUARIOS_VALIDOS[usuario]["rol"]
        st.session_state.email = USUARIOS_VALIDOS[usuario]["email"]
    else:
        st.session_state.nombre = "Usuario Invitado"
        st.session_state.rol = "invitado"
        st.session_state.email = "invitado@laboratorio.com"
    
    # Registrar el inicio de sesión
    registrar_acceso(usuario, es_invitado)

def cerrar_sesion():
    """Cierra la sesión actual"""
    for key in ['autenticado', 'usuario', 'nombre', 'rol', 'email', 'es_invitado', 'hora_inicio']:
        if key in st.session_state:
            del st.session_state[key]

def esta_autenticado():
    """Verifica si el usuario está autenticado"""
    return st.session_state.get('autenticado', False)

def obtener_info_usuario():
    """Obtiene información del usuario actual"""
    if esta_autenticado():
        return {
            'usuario': st.session_state.get('usuario', ''),
            'nombre': st.session_state.get('nombre', ''),
            'rol': st.session_state.get('rol', ''),
            'email': st.session_state.get('email', ''),
            'es_invitado': st.session_state.get('es_invitado', False),
            'hora_inicio': st.session_state.get('hora_inicio', '')
        }
    return None

def tiempo_sesion_restante():
    """Calcula el tiempo restante de sesión (especialmente para invitados)"""
    if esta_autenticado() and st.session_state.get('es_invitado', False):
        tiempo_transcurrido = datetime.now() - st.session_state.hora_inicio
        tiempo_restante = timedelta(hours=24) - tiempo_transcurrido
        if tiempo_restante.total_seconds() > 0:
            horas = int(tiempo_restante.total_seconds() // 3600)
            minutos = int((tiempo_restante.total_seconds() % 3600) // 60)
            return f"{horas}h {minutos}m"
    return None

def verificar_sesion_valida():
    """Verifica si la sesión sigue siendo válida"""
    if esta_autenticado():
        if st.session_state.get('es_invitado', False):
            tiempo_transcurrido = datetime.now() - st.session_state.hora_inicio
            if tiempo_transcurrido > timedelta(hours=24):
                cerrar_sesion()
                st.warning("⚠️ Tu sesión de invitado ha expirado. Por favor, inicia sesión nuevamente.")
                return False
    return esta_autenticado()

def registrar_acceso(usuario, es_invitado):
    """Registra el acceso en el sistema (para auditoría)"""
    registro = {
        'usuario': usuario,
        'es_invitado': es_invitado,
        'fecha_hora': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'ip': st.experimental_get_query_params().get('ip', ['desconocido'])[0]
    }
    
    # En una aplicación real, esto se guardaría en una base de datos
    # Por ahora, solo mostramos en consola
    print(f"📋 Acceso registrado: {registro}")

# ==============================================================================
#                   INTERFAZ DE AUTENTICACIÓN
# ==============================================================================

def mostrar_pagina_login():
    """Muestra la página de inicio de sesión"""
    
    st.markdown("""
    <style>
        .login-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 2rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .login-form {
            margin-top: 2rem;
        }
        .login-footer {
            text-align: center;
            margin-top: 2rem;
            font-size: 0.9rem;
            color: #666;
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    
    # Logo y título
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/1998/1998678.png", width=100)
    
    st.markdown('<div class="login-header">', unsafe_allow_html=True)
    st.title("🔐 Acceso al Sistema")
    st.markdown("**Sistema de Análisis k0-INAA**")
    st.markdown("</div>", unsafe_allow_html=True)
    
    # Pestañas para diferentes métodos de acceso
    tab1, tab2 = st.tabs(["👤 Usuario Registrado", "🎫 Acceso Temporal"])
    
    with tab1:
        st.markdown('<div class="login-form">', unsafe_allow_html=True)
        
        with st.form("form_login"):
            st.subheader("Iniciar Sesión")
            
            usuario = st.text_input("Usuario", placeholder="Ingrese su usuario")
            password = st.text_input("Contraseña", type="password", placeholder="Ingrese su contraseña")
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                submit_login = st.form_submit_button("🔑 Iniciar Sesión", type="primary", use_container_width=True)
            
            with col_btn2:
                submit_guest = st.form_submit_button("👁️ Mostrar/Ocultar", type="secondary", use_container_width=True)
            
            if submit_login:
                if not usuario or not password:
                    st.error("⚠️ Por favor, ingrese usuario y contraseña")
                elif verificar_credenciales(usuario, password):
                    crear_sesion(usuario, es_invitado=False)
                    st.success(f"✅ ¡Bienvenido, {USUARIOS_VALIDOS[usuario]['nombre']}!")
                    st.balloons()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Usuario o contraseña incorrectos")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    with tab2:
        st.markdown('<div class="login-form">', unsafe_allow_html=True)
        
        with st.form("form_invitado"):
            st.subheader("Acceso Temporal")
            st.info("""
            **Para evaluación o demostración:**
            - Acceso limitado a 24 horas
            - Funcionalidades básicas
            - Sin capacidad de exportar datos sensibles
            """)
            
            token = st.text_input(
                "Token de Acceso", 
                placeholder="Ingrese el token proporcionado",
                help=f"Token válido hasta: {TOKEN_INVITADO_VALIDO_HASTA.strftime('%d/%m/%Y')}"
            )
            
            if st.form_submit_button("🎫 Acceder como Invitado", type="primary", use_container_width=True):
                if not token:
                    st.error("⚠️ Por favor, ingrese el token")
                elif verificar_token_invitado(token):
                    crear_sesion("invitado", es_invitado=True)
                    st.success("✅ ¡Acceso temporal concedido!")
                    st.info("🔔 **Nota:** Esta sesión es válida por 24 horas")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ Token inválido o expirado")
        
        st.markdown("</div>", unsafe_allow_html=True)
    
    # Información adicional
    st.markdown('<div class="login-footer">', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("""
    **Credenciales de prueba:**
    - Usuario: `admin` / Contraseña: `admin123`
    - Usuario: `usuario` / Contraseña: `123456`
    
    **Token de invitado:** `K0-INAA-2024-TEMP-ACCESS`
    """)
    st.markdown("</div>", unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

def mostrar_barra_estado():
    """Muestra la barra de estado con información del usuario"""
    if esta_autenticado():
        info_usuario = obtener_info_usuario()
        
        # CSS para la barra de estado
        st.markdown("""
        <style>
            .status-bar {
                background: linear-gradient(90deg, #1E3A8A, #3B82F6);
                color: white;
                padding: 0.5rem 1rem;
                border-radius: 5px;
                margin-bottom: 1rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .user-info {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .user-role {
                background: rgba(255, 255, 255, 0.2);
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 0.8rem;
            }
            .session-time {
                font-size: 0.8rem;
                opacity: 0.8;
            }
        </style>
        """, unsafe_allow_html=True)
        
        # Contenido de la barra
        tiempo_restante = tiempo_sesion_restante()
        tiempo_texto = f"⏳ {tiempo_restante}" if tiempo_restante else ""
        
        html_content = f"""
        <div class="status-bar">
            <div class="user-info">
                <span>👤 {info_usuario['nombre']}</span>
                <span class="user-role">{info_usuario['rol'].upper()}</span>
            </div>
            <div class="session-time">
                {tiempo_texto}
                <button onclick="location.href='?logout=true'" style="
                    background: rgba(255, 255, 255, 0.2);
                    border: none;
                    color: white;
                    padding: 5px 10px;
                    border-radius: 3px;
                    cursor: pointer;
                    margin-left: 10px;
                ">🚪 Salir</button>
            </div>
        </div>
        """
        
        st.markdown(html_content, unsafe_allow_html=True)
        
        # Manejar logout
        if st.button("🚪 Cerrar Sesión", key="logout_btn"):
            cerrar_sesion()
            st.success("✅ Sesión cerrada correctamente")
            time.sleep(1)
            st.rerun()

def verificar_permisos(rol_requerido="usuario"):
    """Verifica si el usuario tiene los permisos necesarios"""
    if not esta_autenticado():
        return False
    
    info_usuario = obtener_info_usuario()
    roles = {
        "invitado": 0,
        "usuario": 1,
        "admin": 2
    }
    
    nivel_actual = roles.get(info_usuario['rol'], 0)
    nivel_requerido = roles.get(rol_requerido, 1)
    
    return nivel_actual >= nivel_requerido

def mostrar_acceso_denegado():
    """Muestra página de acceso denegado"""
    st.error("⛔ **ACCESO DENEGADO**")
    st.warning("""
    No tienes permisos para acceder a esta sección.
    
    **Posibles razones:**
    1. Tu rol de usuario no tiene suficientes privilegios
    2. Estás usando una cuenta de invitado con acceso limitado
    3. Tu sesión ha expirado
    
    **Solución:**
    - Contacta al administrador del sistema
    - Inicia sesión con una cuenta con mayores privilegios
    """)
    
    if st.button("🔙 Volver al inicio"):
        for key in list(st.session_state.keys()):
            if key != 'autenticado' and key != 'usuario':
                del st.session_state[key]
        st.rerun()

# ==============================================================================
#                   DECORADOR PARA PROTEGER FUNCIONES
# ==============================================================================

def requiere_autenticacion(func):
    """Decorador para proteger funciones que requieren autenticación"""
    def wrapper(*args, **kwargs):
        if not esta_autenticado():
            mostrar_pagina_login()
            return None
        elif not verificar_sesion_valida():
            mostrar_pagina_login()
            return None
        else:
            return func(*args, **kwargs)
    return wrapper

def requiere_rol(rol_requerido="usuario"):
    """Decorador para proteger funciones que requieren un rol específico"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not esta_autenticado():
                mostrar_pagina_login()
                return None
            elif not verificar_sesion_valida():
                mostrar_pagina_login()
                return None
            elif not verificar_permisos(rol_requerido):
                mostrar_acceso_denegado()
                return None
            else:
                return func(*args, **kwargs)
        return wrapper
    return decorator

# ==============================================================================
#                   INICIALIZACIÓN DEL SISTEMA
# ==============================================================================

def inicializar_auth():
    """Inicializa el sistema de autenticación"""
    # Verificar si hay parámetros de logout en la URL
    query_params = st.experimental_get_query_params()
    if 'logout' in query_params:
        cerrar_sesion()
        st.experimental_set_query_params()
        st.rerun()
    
    # Verificar sesión válida
    if not verificar_sesion_valida():
        mostrar_pagina_login()
        return False
    
    return True

# ==============================================================================
#                   FUNCIONES DE ADMINISTRACIÓN (solo para admin)
# ==============================================================================

@requiere_rol("admin")
def mostrar_panel_administracion():
    """Muestra el panel de administración"""
    st.subheader("👨‍💼 Panel de Administración")
    
    # Pestañas del panel admin
    tab1, tab2, tab3 = st.tabs(["📊 Estadísticas", "👥 Gestión de Usuarios", "🔒 Configuración"])
    
    with tab1:
        st.write("**Estadísticas de uso:**")
        # Aquí irían estadísticas reales
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Usuarios activos", "2")
        with col2:
            st.metric("Sesiones hoy", "5")
        with col3:
            st.metric("Archivos procesados", "128")
    
    with tab2:
        st.write("**Usuarios registrados:**")
        
        usuarios_data = []
        for usuario, info in USUARIOS_VALIDOS.items():
            usuarios_data.append({
                "Usuario": usuario,
                "Nombre": info["nombre"],
                "Rol": info["rol"],
                "Email": info["email"]
            })
        
        st.dataframe(pd.DataFrame(usuarios_data), use_container_width=True)
        
        # Agregar nuevo usuario
        with st.expander("➕ Agregar nuevo usuario"):
            with st.form("form_nuevo_usuario"):
                nuevo_usuario = st.text_input("Nuevo usuario")
                nuevo_nombre = st.text_input("Nombre completo")
                nuevo_email = st.text_input("Email")
                nuevo_password = st.text_input("Contraseña", type="password")
                nuevo_rol = st.selectbox("Rol", ["usuario", "admin"])
                
                if st.form_submit_button("Crear usuario"):
                    st.success(f"Usuario {nuevo_usuario} creado (simulación)")
    
    with tab3:
        st.write("**Configuración del sistema:**")
        
        # Configuración de tokens
        nuevo_token = st.text_input("Nuevo token de invitado", value=TOKEN_INVITADO)
        nueva_fecha = st.date_input("Válido hasta", value=TOKEN_INVITADO_VALIDO_HASTA)
        
        if st.button("🔄 Actualizar configuración"):
            st.success("Configuración actualizada (simulación)")
