// Función auxiliar para generar números enteros aleatorios dentro de un rango
function generarNumeroAleatorio(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ------------------- Funciones de Cálculo y Validación -------------------

// Función para verificar si una cadena es hexadecimal
function validarHex(str) {
    // Permite 0-9, a-f, A-F.
    return /^[0-9A-Fa-f]*$/.test(str);
}

function generarTOS() {
    let dscp = parseInt(document.getElementById("dscp").value);
    let ecn = parseInt(document.getElementById("ecn").value);

    // DSCP (6 bits) se desplaza 2 bits a la izquierda, ECN (2 bits) se suma.
    let tos = (dscp << 2) | ecn;
    document.getElementById("tos").value = tos;
}

function calcularLongitudTotal() {
    let ihlElement = document.getElementById("ihl");
    let datos = document.getElementById("datos").value;
    let optionsHex = document.getElementById("options").value.toUpperCase().trim();

    // 1. CÁLCULO PRELIMINAR DE LONGITUDES
    let ihl = parseInt(ihlElement.value);
    let longitudEncabezado = ihl * 4;
    let longitudDatos = datos.length; 
    
    // Asumimos 0 si la entrada Hex es vacía o tiene longitud impar (lo validaremos después)
    let longitudOpciones = (optionsHex.length % 2 === 0 && validarHex(optionsHex)) ? optionsHex.length / 2 : 0; 
    
    // Espacio máximo disponible para opciones (40 bytes fijos - 20 bytes = 20 bytes máx. de Opciones)
    let maxLongitudOpciones = longitudEncabezado - 20;


    // 2. VALIDACIONES DE ERRORES (Los errores reales se manejarán en generarDatagrama)
    
    // Si IHL=5, no debe haber opciones.
    if (ihl === 5 && longitudOpciones > 0) {
        // Marcamos IHL inválido para opciones
        document.getElementById("totalLength").value = "IHL-ERROR"; 
        return;
    }

    // Si las opciones exceden el espacio del IHL
    if (longitudOpciones > maxLongitudOpciones) {
        // Marcamos Opciones demasiado largas
        document.getElementById("totalLength").value = "OPTS-ERROR"; 
        return;
    }

    // Si el Hex es inválido (longitud impar o caracteres no hex)
    if (!validarHex(optionsHex) || optionsHex.length % 2 !== 0) {
         document.getElementById("totalLength").value = "HEX-ERROR";
         return;
    }

    // 3. CALCULO FINAL
    let total = longitudEncabezado + longitudDatos;

    // Validación de longitud total máxima (65535)
    if (total > 65535) {
        document.getElementById("totalLength").value = "MAX-ERROR";
        return;
    }

    document.getElementById("totalLength").value = total;
}

// Checksum: Simulación. El cálculo real requiere todos los valores del encabezado.
function calcularChecksumHeader() {
    // Genera un valor simulado de 16 bits en formato hexadecimal.
    return generarNumeroAleatorio(10000, 65535).toString(16).toUpperCase().padStart(4, '0');
}

function validarIP(ip) {
    const regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    if (!regex.test(ip)) return false;

    return ip.split('.').every(octet => {
        const num = parseInt(octet);
        return num >= 0 && num <= 255;
    });
}


// ------------------- Función de Generación Aleatoria -------------------

function generarValoresAleatorios() {
    document.getElementById("identification").value = generarNumeroAleatorio(0, 65535);
    document.getElementById("ttl").value = generarNumeroAleatorio(1, 255);
    
    // Flags (Bandera DF y MF) - Genera 0 o 1
    document.getElementById("flagDF").value = generarNumeroAleatorio(0, 1);
    document.getElementById("flagMF").value = generarNumeroAleatorio(0, 1);

    document.getElementById("fragmentOffset").value = generarNumeroAleatorio(0, 8191);

    alert("Valores de Identificación, TTL, Flags y Desplazamiento generados aleatoriamente.");
}


// ------------------- Función Principal para Generar Datagrama -------------------

function generarDatagrama() {

    // Forzar el cálculo y la validación de IHL/Opciones antes de continuar
    calcularLongitudTotal(); 

    // 1. Validaciones Críticas

    // Revalidamos el campo totalLength para manejar errores
    const totalLengthValue = document.getElementById("totalLength").value;
    const totalLength = parseInt(totalLengthValue);

    if (totalLengthValue.includes("ERROR") || isNaN(totalLength) || totalLength === 0) {
         let errorMessage = "⛔ ERROR en la configuración de Longitud Total. ";
         
         if (totalLengthValue === "HEX-ERROR") {
             errorMessage += "Las Opciones deben ser Hexadecimales válidas y tener longitud par.";
         } else if (totalLengthValue === "IHL-ERROR") {
             errorMessage += "No puede haber Opciones si IHL es 5 (20 bytes).";
         } else if (totalLengthValue === "OPTS-ERROR") {
             errorMessage += `Las Opciones (${document.getElementById("options").value.length / 2} bytes) exceden el espacio disponible por el IHL seleccionado.`;
         } else if (totalLengthValue === "MAX-ERROR") {
             errorMessage += "La longitud total excede el máximo permitido (65535 bytes).";
         } else {
             errorMessage += "Asegúrate de que todos los campos y el IHL estén correctamente configurados.";
         }
         alert(errorMessage);
         return;
    }
    
    if (document.getElementById("tos").value === "") {
        alert("⛔ ERROR: Primero genera el campo TOS (Tipo de Servicio).");
        return;
    }

    // Validación de rango de Identificación
    const identification = parseInt(document.getElementById("identification").value);
    if (isNaN(identification) || identification < 0 || identification > 65535) {
        alert("⛔ ERROR: El campo Identificación debe ser un número entero entre 0 y 65535.");
        return;
    }

    const srcIP = document.getElementById("src").value;
    const dstIP = document.getElementById("dst").value;
    if (!validarIP(srcIP) || !validarIP(dstIP)) {
        alert("⛔ ERROR: Las direcciones IP de Origen o Destino no tienen un formato válido.");
        return;
    }

    // 2. Obtener y calcular valores finales
    let checksum = calcularChecksumHeader();
    let ihl = parseInt(document.getElementById("ihl").value);
    let ttl = document.getElementById("ttl").value;
    let fragmentOffset = document.getElementById("fragmentOffset").value;
    let optionsHex = document.getElementById("options").value.toUpperCase().trim();
    let longitudOpciones = optionsHex.length / 2;

    
    // COMBINACIÓN DE BANDERAS (FLAGS)
    const dfValue = parseInt(document.getElementById("flagDF").value);
    const mfValue = parseInt(document.getElementById("flagMF").value);
    const flagsCombined = (mfValue * 4) + (dfValue * 2); 
    
    let flagDFString = dfValue === 1 ? '1 (No fragmentar - DF=1)' : '0 (Permitir fragmentación - DF=0)';
    let flagMFString = mfValue === 1 ? '1 (Hay más fragmentos - MF=1)' : '0 (Último fragmento - MF=0)';
    
    // CONVERSIÓN DE DATOS (ASCII) A HEXADECIMAL para su despliegue
    let datos = document.getElementById("datos").value;
    let datosHex = '';
    for (let i = 0; i < datos.length; i++) {
        datosHex += datos.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
    }


    // 3. Formatear la salida (Datagrama Completo)
    let salida = `
// ------------------- Encabezado IPv4 -------------------
Versión: 4
IHL: ${ihl} (${ihl * 4} bytes)
TOS: ${document.getElementById("tos").value}
Longitud Total: ${totalLength} bytes
Identificación: ${identification}

Flags (Bandera, 3 bits): ${flagsCombined}
  > Bit 0 (Reservado): 0
  > Bit 1 (DF): ${flagDFString}
  > Bit 2 (MF): ${flagMFString}

Fragment Offset: ${fragmentOffset} (unidades de 8 bytes)
TTL (Tiempo de Vida): ${ttl}
Protocolo: ${document.getElementById("protocol").value}
Checksum (Header): 0x${checksum} (Simulado)
IP Origen: ${srcIP}
IP Destino: ${dstIP}

Opciones (Hexadecimal): 0x${optionsHex || '00'}
  > Longitud de Opciones: ${longitudOpciones} bytes

// ------------------- Carga Útil (Datos) -------------------
Datos (ASCII): "${datos}"
Datos (Hexadecimal): 0x${datosHex || '00'}
  > Longitud de Datos: ${datos.length} bytes

Longitud Total del Datagrama (bytes): ${totalLength}
    `;

    document.getElementById("resultado").innerText = salida;
    document.getElementById("modal").style.display = "flex";
}

function cerrarModal() {
    document.getElementById("modal").style.display = "none";
}

document.addEventListener('DOMContentLoaded', calcularLongitudTotal);